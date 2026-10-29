import { randomUUID } from "node:crypto";
import { type ModuleCatalog, type Policy, parseWire } from "@one-control/module-contracts";
import { type ModulePlatform, resolveModulePlan } from "@one-control/modules";
import { z } from "zod";
import type { Config } from "../../../apps/control-plane/src/config.js";
import type { Database, TransactionQuery } from "../../../apps/control-plane/src/database.js";
import { audit } from "../../../apps/control-plane/src/routes/context.js";
import { type Actor, ApiError, hash } from "../../../apps/control-plane/src/security.js";
import { desktopPolicyForEnrollment } from "../../desktop-policies/server/control.js";
import { type NativeJobBoundary, nativeJobControl } from "../../native-dispatch/server/jobs.js";
import {
  nativeReportSchema,
  recordNativeObservation,
} from "../../native-observations/server/observations.js";
import { recoveryKeyInput, saveRecoveryKey } from "../../recovery-escrow/server/escrow.js";
import { admittedCatalog } from "./catalog.js";
import { type NativeAuthority, nativeAuthority, nativeDigest, nativeRoles } from "./signing.js";

type Enrollment = { id: string; scope_id: string; device_id: string; platform: string; machine_id: string };
type Publication = {
  id: string;
  scope_id: string;
  kind: "catalog" | "policy";
  enrollment_id: string | null;
  custody_reference: string;
  root_version: string;
  authority_epoch: string;
  revision: string;
  authorization_version: string;
  request_hash: string;
  issuer: string;
  subject: string;
  predecessor: string | null;
  state: string;
  protected_bytes: Buffer;
  payload: Buffer;
  payload_digest: string;
  envelope: Buffer | null;
  projection: ModuleCatalog | Policy;
  deadline: Date;
  expires_at: Date;
};
type Selection = {
  version: string;
  catalog_id: string;
  enabled: Record<string, string>;
  disabled: string[];
  allowed_permissions: string[];
  bootstrap_version: string;
  issuer: string;
  subject: string;
};
type Boundary = {
  scope: (
    tx: TransactionQuery,
    actor: Actor,
    id: string,
    permission: "view" | "configure",
  ) => Promise<{ version: string }>;
  credential: (tx: TransactionQuery, digest: string) => Promise<Enrollment>;
  selectionGrant: (tx: TransactionQuery, id: string, issuer: string, subject: string) => Promise<void>;
  distribution: (tx: TransactionQuery, id: string) => Promise<void>;
  reportAdmission: (tx: TransactionQuery, id: string, kind: "heartbeat" | "inventory") => Promise<void>;
  advance: (tx: TransactionQuery, id: string, expected: string) => Promise<string>;
  command: NativeJobBoundary["command"];
  dispatch: (tx: TransactionQuery, id: string) => Promise<void>;
  escrowAdmission: (tx: TransactionQuery, id: string) => Promise<void>;
};
const version = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const platform = z.enum(["win-x64", "win-arm64", "osx-x64", "osx-arm64", "linux-x64", "linux-arm64"]);
const moduleId = z
  .string()
  .regex(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/)
  .max(96);
const moduleVersion = z.string().regex(/^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$/);
const actorKey = (actor: Pick<Actor, "issuer" | "id">) => JSON.stringify([actor.issuer, actor.id]);
async function now(tx: TransactionQuery) {
  const [time] = await tx.query<{ seconds: string }>(
    "SELECT floor(extract(epoch from clock_timestamp()))::bigint::text AS seconds",
  );
  return Number(time!.seconds);
}
async function activeCustody(tx: TransactionQuery, authority: NativeAuthority) {
  const [row] = await tx.query<{
    state: string;
    custody_reference: string;
    root_version: string;
    authority_epoch: string;
    trust_digest: string;
  }>(
    "SELECT r.state,r.custody_reference,r.root_version::text,r.authority_epoch::text,c.trust_digest FROM authority_runtime r LEFT JOIN native_custody_records c ON c.reference=r.custody_reference WHERE singleton=true",
  );
  if (
    row?.state !== "active" ||
    row.custody_reference !== authority.reference ||
    row.root_version !== authority.rootVersion ||
    row.authority_epoch !== authority.epoch ||
    row.trust_digest !== nativeDigest(Buffer.from(JSON.stringify(authority.publicTrust())))
  )
    throw new ApiError(503, "native_custody_inactive");
}
async function publication(tx: TransactionQuery, id: string) {
  const [row] = await tx.query<Publication>(
    "SELECT *,revision::text,root_version::text,authority_epoch::text,authorization_version::text FROM native_publications WHERE id=$1",
    [id],
  );
  if (!row) throw new ApiError(404, "native_publication_not_found");
  return row;
}
async function head(tx: TransactionQuery, kind: "catalog" | "policy", id: string) {
  const [row] = await tx.query<{ publication_id: string }>(
    kind === "catalog"
      ? "SELECT publication_id FROM native_catalog_heads WHERE scope_id=$1"
      : "SELECT publication_id FROM native_policy_heads WHERE enrollment_id=$1",
    [id],
  );
  return row?.publication_id ?? null;
}
async function revision(tx: TransactionQuery, scope: string, kind: string, subject: string) {
  const [row] = await tx.query<{ revision: string }>(
    `INSERT INTO native_publication_sequences(scope_id,kind,subject,revision) VALUES($1,$2,$3,1)
  ON CONFLICT(scope_id,kind,subject) DO UPDATE SET revision=native_publication_sequences.revision+1 WHERE native_publication_sequences.revision<18446744073709551615 RETURNING revision::text`,
    [scope, kind, subject],
  );
  if (!row) throw new ApiError(409, "native_revision_exhausted");
  return row.revision;
}
async function storeIntent(
  tx: TransactionQuery,
  authority: NativeAuthority,
  input: {
    id: string;
    scope: string;
    kind: "catalog" | "policy";
    enrollmentId?: string;
    revision: string;
    authorizationVersion: string;
    requestHash: string;
    actor: Pick<Actor, "issuer" | "id">;
    predecessor: string | null;
    payload: Buffer;
    projection: ModuleCatalog | Policy;
    time: number;
  },
) {
  await tx.query(
    `INSERT INTO native_publications(id,scope_id,kind,enrollment_id,custody_reference,root_version,authority_epoch,revision,authorization_version,request_hash,issuer,subject,predecessor,state,protected_bytes,payload,payload_digest,projection,deadline,expires_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending',$14,$15,$16,$17,to_timestamp($18),to_timestamp($19))`,
    [
      input.id,
      input.scope,
      input.kind,
      input.enrollmentId ?? null,
      authority.reference,
      authority.rootVersion,
      authority.epoch,
      input.revision,
      input.authorizationVersion,
      input.requestHash,
      input.actor.issuer,
      input.actor.id,
      input.predecessor,
      authority.header(input.kind),
      input.payload,
      nativeDigest(input.payload),
      JSON.stringify(input.projection),
      input.time + 30,
      input.projection.expiresAt,
    ],
  );
  return publication(tx, input.id);
}
async function signIntent(authority: NativeAuthority, intent: Publication) {
  const remaining = new Date(intent.deadline).getTime() - Date.now();
  if (remaining <= 0) throw new ApiError(409, "native_publication_expired");
  return authority.sign(
    intent.kind,
    Buffer.from(intent.protected_bytes),
    Buffer.from(intent.payload),
    AbortSignal.timeout(Math.min(5000, remaining)),
  );
}
async function finalize(
  tx: TransactionQuery,
  authority: NativeAuthority,
  intent: Publication,
  raw: Buffer,
  authorizationVersion: string,
) {
  await activeCustody(tx, authority);
  const current = await publication(tx, intent.id);
  const currentHead = await head(
    tx,
    current.kind,
    current.kind === "catalog" ? current.scope_id : current.enrollment_id!,
  );
  if (current.state === "published" && currentHead === current.id) return current;
  if (
    current.state !== "pending" ||
    current.authorization_version !== authorizationVersion ||
    currentHead !== current.predecessor ||
    new Date(current.deadline).getTime() <= Date.now()
  )
    throw new ApiError(409, "native_publication_superseded");
  await activeCustody(tx, authority);
  const verified = authority.verify(raw, nativeRoles[current.kind], await now(tx));
  if (
    !verified.payload.equals(Buffer.from(current.payload)) ||
    !verified.protectedBytes.equals(Buffer.from(current.protected_bytes))
  )
    throw new ApiError(503, "native_signing_intent_mismatch");
  const committed = await tx.query(
    "UPDATE native_publications SET state='published',envelope=$2,published_at=clock_timestamp() WHERE id=$1 AND deadline>clock_timestamp() AND expires_at>clock_timestamp() RETURNING id",
    [current.id, raw],
  );
  if (!committed.length) throw new ApiError(409, "native_publication_expired");
  if (current.kind === "catalog")
    await tx.query(
      "INSERT INTO native_catalog_heads(scope_id,publication_id) VALUES($1,$2) ON CONFLICT(scope_id) DO UPDATE SET publication_id=EXCLUDED.publication_id",
      [current.scope_id, current.id],
    );
  else
    await tx.query(
      "INSERT INTO native_policy_heads(enrollment_id,publication_id) VALUES($1,$2) ON CONFLICT(enrollment_id) DO UPDATE SET publication_id=EXCLUDED.publication_id",
      [current.enrollment_id, current.id],
    );
  return { ...current, state: "published", envelope: raw };
}
function catalogResult(row: Publication) {
  return {
    publicationId: row.id,
    revision: row.revision,
    digest: row.payload_digest,
    envelope: Buffer.from(row.envelope!).toString("base64url"),
    expiresAt: new Date(row.expires_at).toISOString(),
    entries: (row.projection as ModuleCatalog).entries,
  };
}

/** Called only through ModuleControl; boundary callbacks retain its common lock and grant order. */
export function nativePublicationControl(db: Database, config: Config, boundary: Boundary) {
  async function nativeContext(tx: TransactionQuery, authority: NativeAuthority, credentialHash: string) {
    const enrollment = await boundary.credential(tx, credentialHash);
    await activeCustody(tx, authority);
    await boundary.distribution(tx, enrollment.scope_id);
    const [selection] = await tx.query<Selection>(
      "SELECT version::text,catalog_id,enabled,disabled,allowed_permissions,bootstrap_version,issuer,subject FROM native_selections WHERE scope_id=$1 AND platform=$2",
      [enrollment.scope_id, enrollment.platform],
    );
    if (!selection) throw new ApiError(409, "native_selection_unconfigured");
    await boundary.selectionGrant(tx, enrollment.scope_id, selection.issuer, selection.subject);
    const catalog = await publication(tx, selection.catalog_id);
    if (
      catalog.state !== "published" ||
      catalog.id !== (await head(tx, "catalog", enrollment.scope_id)) ||
      new Date(catalog.expires_at).getTime() <= Date.now()
    )
      throw new ApiError(409, "native_catalog_unavailable");
    const [scope] = await tx.query<{ version: string; permission_ceiling: string[] }>(
      "SELECT version::text,permission_ceiling FROM management_scopes WHERE id=$1",
      [enrollment.scope_id],
    );
    if (selection.allowed_permissions.some((permission) => !scope!.permission_ceiling.includes(permission)))
      throw new ApiError(403, "native_permission_revoked");
    return { enrollment, selection, catalog, scope: scope! };
  }
  return {
    ...nativeJobControl(db, config, {
      credential: boundary.credential,
      command: boundary.command,
      async policy(tx, credentialHash, digest) {
        const authority = await nativeAuthority(config);
        const { enrollment, selection, catalog } = await nativeContext(tx, authority, credentialHash);
        await boundary.dispatch(tx, enrollment.scope_id);
        const id = await head(tx, "policy", enrollment.id);
        if (!id) throw new ApiError(409, "native_policy_unavailable");
        const current = await publication(tx, id);
        if (
          current.state !== "published" ||
          current.payload_digest !== digest ||
          current.request_hash !== hash(JSON.stringify([enrollment.id, selection.version, catalog.id])) ||
          new Date(current.expires_at).getTime() <= Date.now()
        )
          throw new ApiError(409, "native_policy_changed");
        return { enrollment, policy: current.projection as Policy };
      },
    }),
    async nativeReportState(credential: string) {
      return db.transaction(async (tx) => {
        const enrollment = await boundary.credential(tx, hash(credential));
        await boundary.reportAdmission(tx, enrollment.scope_id, "heartbeat");
        const [stream] = await tx.query<{ sequence: string; digest: string; response: unknown }>(
          "SELECT sequence::text,digest,response FROM native_report_streams WHERE enrollment_id=$1",
          [enrollment.id],
        );
        return {
          enrollmentId: enrollment.id,
          sequence: stream?.sequence ?? "0",
          digest: stream?.digest ?? null,
          response: stream?.response ?? null,
        };
      });
    },
    async escrowNativeKey(credential: string, raw: unknown) {
      const input = recoveryKeyInput.parse(raw),
        authority = await nativeAuthority(config);
      return db.transaction(async (tx) => {
        const { enrollment, selection, catalog } = await nativeContext(tx, authority, hash(credential));
        await boundary.escrowAdmission(tx, enrollment.scope_id);
        const id = await head(tx, "policy", enrollment.id);
        if (!id) throw new ApiError(409, "native_policy_unavailable");
        const publicationRow = await publication(tx, id),
          policy = publicationRow.projection as Policy;
        if (
          publicationRow.state !== "published" ||
          publicationRow.payload_digest !== input.policyDigest ||
          publicationRow.request_hash !==
            hash(JSON.stringify([enrollment.id, selection.version, catalog.id])) ||
          new Date(publicationRow.expires_at).getTime() <= Date.now()
        )
          throw new ApiError(409, "native_policy_changed");
        if (
          !policy.enabled.bitlocker ||
          policy.disabled.includes("bitlocker") ||
          !policy.allowedPermissions.includes("bitlocker.escrow")
        )
          throw new ApiError(403, "native_escrow_not_selected");
        const desktop = await desktopPolicyForEnrollment(tx, enrollment.scope_id, enrollment.id);
        if (!desktop.document.hardening.bitlocker.backupRecoveryKey)
          throw new ApiError(403, "recovery_key_backup_disabled");
        return saveRecoveryKey(tx, config, enrollment, input);
      });
    },
    async nativeReport(credential: string, raw: unknown) {
      const input = nativeReportSchema.parse(raw),
        authority = await nativeAuthority(config);
      return db.transaction(async (tx) => {
        const { enrollment, selection, catalog } = await nativeContext(tx, authority, hash(credential));
        await boundary.reportAdmission(tx, enrollment.scope_id, input.kind);
        const policyId = await head(tx, "policy", enrollment.id);
        if (!policyId) throw new ApiError(409, "native_policy_unavailable");
        const policy = await publication(tx, policyId),
          document = policy.projection as Policy;
        if (
          policy.state !== "published" ||
          policy.payload_digest !== input.policyDigest ||
          policy.request_hash !== hash(JSON.stringify([enrollment.id, selection.version, catalog.id])) ||
          new Date(policy.expires_at).getTime() <= Date.now()
        )
          throw new ApiError(409, "native_policy_changed");
        if (
          input.kind === "inventory" &&
          (document.enabled.inventory !== input.moduleVersion ||
            document.disabled.includes("inventory") ||
            !document.allowedPermissions.includes("inventory.read"))
        )
          throw new ApiError(403, "native_inventory_not_selected");
        return recordNativeObservation(tx, enrollment, policy.id, input);
      });
    },
    async activateNativeCustody(actor: Actor) {
      if (!actor.roles.has("operator")) throw new ApiError(403, "forbidden");
      const authority = await nativeAuthority(config);
      if (
        !authority.configuration.administrators.some(
          (value) => value.issuer === actor.issuer && value.subject === actor.id,
        )
      )
        throw new ApiError(403, "native_custody_admin_required");
      return db.transaction(async (tx) => {
        const [runtime] = await tx.query<{ state: string; custody_reference: string }>(
          "SELECT state,custody_reference FROM authority_runtime WHERE singleton=true FOR UPDATE",
        );
        if (runtime?.state === "quarantined") throw new ApiError(503, "authority_quarantined");
        if (runtime?.state === "active") {
          await activeCustody(tx, authority);
          return { state: "active", rootVersion: authority.rootVersion, authorityEpoch: authority.epoch };
        }
        const trust = Buffer.from(JSON.stringify(authority.publicTrust()));
        await tx.query(
          "INSERT INTO native_custody_records(reference,root_version,authority_epoch,public_trust,trust_digest) VALUES($1,$2,$3,$4,$5)",
          [
            authority.reference,
            authority.rootVersion,
            authority.epoch,
            trust.toString("utf8"),
            nativeDigest(trust),
          ],
        );
        await tx.query(
          "UPDATE authority_runtime SET state='active',custody_reference=$1,root_version=$2,authority_epoch=$3 WHERE singleton=true",
          [authority.reference, authority.rootVersion, authority.epoch],
        );
        await audit(tx, actorKey(actor), "native.custody_activated", "authority", {
          rootVersion: authority.rootVersion,
          authorityEpoch: authority.epoch,
        });
        return { state: "active", rootVersion: authority.rootVersion, authorityEpoch: authority.epoch };
      });
    },
    async nativeStatus(actor: Actor, id: string) {
      return db.transaction(async (tx) => {
        const scope = await boundary.scope(tx, actor, id, "view");
        const current = await head(tx, "catalog", id);
        return {
          version: scope.version,
          catalog: current ? catalogResult(await publication(tx, current)) : null,
          selections: await tx.query(
            "SELECT platform,version::text,catalog_id,enabled,disabled,allowed_permissions,bootstrap_version FROM native_selections WHERE scope_id=$1 ORDER BY platform",
            [id],
          ),
        };
      });
    },
    async publishNativeCatalog(actor: Actor, id: string, raw: unknown) {
      const input = z
        .strictObject({
          requestId: z.uuid(),
          expectedVersion: version,
          entries: z.array(z.unknown()).max(256),
          attestations: z.array(z.string().max(8388608)).max(512),
          lifetimeSeconds: z.number().int().min(60).max(86400).default(3600),
        })
        .parse(raw);
      const authority = await nativeAuthority(config);
      const requestHash = hash(JSON.stringify(input));
      const intent = await db.transaction(async (tx) => {
        const scope = await boundary.scope(tx, actor, id, "configure");
        await activeCustody(tx, authority);
        const [existing] = await tx.query<Publication>(
          "SELECT *,revision::text,root_version::text,authority_epoch::text,authorization_version::text FROM native_publications WHERE id=$1",
          [input.requestId],
        );
        if (existing) {
          if (
            existing.scope_id !== id ||
            existing.request_hash !== requestHash ||
            existing.issuer !== actor.issuer ||
            existing.subject !== actor.id
          )
            throw new ApiError(409, "native_publication_request_conflict");
          if (existing.state === "published" && existing.id === (await head(tx, "catalog", id)))
            return existing;
          if (existing.state !== "pending" || existing.authorization_version !== scope.version)
            throw new ApiError(409, "native_publication_superseded");
          return existing;
        }
        const nextVersion = await boundary.advance(tx, id, input.expectedVersion);
        const nextRevision = await revision(tx, id, "catalog", id);
        const time = await now(tx);
        const expires = Math.min(time + input.lifetimeSeconds, authority.expires("catalog"));
        let admitted: ReturnType<typeof admittedCatalog>;
        try {
          admitted = admittedCatalog(
            authority,
            input.entries,
            input.attestations,
            nextRevision,
            time,
            expires,
          );
        } catch (error) {
          if (error instanceof ApiError) throw error;
          throw new ApiError(400, "native_catalog_invalid");
        }
        for (const evidence of admitted.evidence)
          await tx.query(
            "INSERT INTO native_publisher_evidence(envelope_digest,custody_reference,key_id,publisher,payload,envelope,projection,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,to_timestamp($8)) ON CONFLICT(envelope_digest) DO NOTHING",
            [
              evidence.envelopeDigest,
              authority.reference,
              evidence.keyId,
              evidence.document.publisher,
              evidence.payload,
              evidence.envelope,
              JSON.stringify(evidence.document),
              evidence.document.expiresAt,
            ],
          );
        return storeIntent(tx, authority, {
          id: input.requestId,
          scope: id,
          kind: "catalog",
          revision: nextRevision,
          authorizationVersion: nextVersion,
          requestHash,
          actor,
          predecessor: await head(tx, "catalog", id),
          payload: admitted.payload,
          projection: admitted.document,
          time,
        });
      });
      if (intent.state === "published") return catalogResult(intent);
      const signed = await signIntent(authority, intent);
      return db.transaction(async (tx) => {
        const scope = await boundary.scope(tx, actor, id, "configure");
        const published = await finalize(tx, authority, intent, signed.envelope, scope.version);
        await audit(tx, actorKey(actor), "native.catalog_published", published.id, {
          scope: id,
          revision: published.revision,
          digest: published.payload_digest,
        });
        return catalogResult(published);
      });
    },
    async configureNativeSelection(actor: Actor, id: string, raw: unknown) {
      const input = z
        .strictObject({
          expectedVersion: version,
          platform,
          catalogId: z.uuid(),
          enabled: z.record(moduleId, moduleVersion),
          disabled: z.array(moduleId).max(256),
          allowedPermissions: z.array(moduleId).max(128),
          bootstrapVersion: moduleVersion,
        })
        .parse(raw);
      const authority = await nativeAuthority(config);
      return db.transaction(async (tx) => {
        await boundary.scope(tx, actor, id, "configure");
        await activeCustody(tx, authority);
        const catalog = await publication(tx, input.catalogId);
        if (
          catalog.scope_id !== id ||
          catalog.kind !== "catalog" ||
          catalog.state !== "published" ||
          catalog.id !== (await head(tx, "catalog", id)) ||
          new Date(catalog.expires_at).getTime() <= Date.now()
        )
          throw new ApiError(409, "native_catalog_unavailable");
        const [scope] = await tx.query<{ permission_ceiling: string[] }>(
          "SELECT permission_ceiling FROM management_scopes WHERE id=$1",
          [id],
        );
        if (input.allowedPermissions.some((permission) => !scope!.permission_ceiling.includes(permission)))
          throw new ApiError(403, "native_permission_not_granted");
        let plan: ReturnType<typeof resolveModulePlan>;
        try {
          plan = resolveModulePlan({
            catalog: (catalog.projection as ModuleCatalog).entries.map((entry) => entry.manifest),
            enabled: input.enabled,
            disabled: input.disabled,
            platform: input.platform as ModulePlatform,
            bootstrapVersion: input.bootstrapVersion,
            allowedPermissions: input.allowedPermissions,
          });
        } catch {
          throw new ApiError(400, "native_selection_invalid");
        }
        const next = await boundary.advance(tx, id, input.expectedVersion);
        await tx.query(
          `INSERT INTO native_selections(scope_id,platform,version,catalog_id,enabled,disabled,allowed_permissions,bootstrap_version,issuer,subject) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          ON CONFLICT(scope_id,platform) DO UPDATE SET version=EXCLUDED.version,catalog_id=EXCLUDED.catalog_id,enabled=EXCLUDED.enabled,disabled=EXCLUDED.disabled,allowed_permissions=EXCLUDED.allowed_permissions,bootstrap_version=EXCLUDED.bootstrap_version,issuer=EXCLUDED.issuer,subject=EXCLUDED.subject`,
          [
            id,
            input.platform,
            next,
            input.catalogId,
            JSON.stringify(input.enabled),
            JSON.stringify(input.disabled),
            JSON.stringify(input.allowedPermissions),
            input.bootstrapVersion,
            actor.issuer,
            actor.id,
          ],
        );
        await audit(tx, actorKey(actor), "native.selection_configured", id, {
          scope: id,
          platform: input.platform,
          version: next,
          enabled: input.enabled,
          disabled: input.disabled,
        });
        return { version: next, plan };
      });
    },
    async issueNativeConfiguration(credential: string, raw: unknown): Promise<Buffer> {
      const { nonce } = z
        .strictObject({
          nonce: z
            .string()
            .regex(/^[A-Za-z0-9_-]{43}$/)
            .refine((value) => Buffer.from(value, "base64url").toString("base64url") === value),
        })
        .parse(raw);
      const credentialHash = hash(credential),
        nonceHash = hash(nonce),
        authority = await nativeAuthority(config);
      const intent = await db.transaction(async (tx) => {
        const context = await nativeContext(tx, authority, credentialHash);
        const { enrollment, selection, catalog, scope } = context;
        const currentId = await head(tx, "policy", enrollment.id);
        if (currentId) {
          const current = await publication(tx, currentId);
          const p = current.projection as Policy;
          if (
            current.state === "published" &&
            p.catalogDigest === catalog.payload_digest &&
            current.request_hash === hash(JSON.stringify([enrollment.id, selection.version, catalog.id])) &&
            new Date(current.expires_at).getTime() > Date.now() + 60000
          )
            return current;
        }
        const requestHash = hash(JSON.stringify([enrollment.id, selection.version, catalog.id]));
        const [pending] = await tx.query<{ id: string }>(
          "SELECT id FROM native_publications WHERE scope_id=$1 AND kind='policy' AND enrollment_id=$2 AND request_hash=$3 AND state='pending' AND authorization_version=$4 AND deadline>clock_timestamp() ORDER BY created_at DESC LIMIT 1",
          [enrollment.scope_id, enrollment.id, requestHash, scope.version],
        );
        if (pending) return publication(tx, pending.id);
        const time = await now(tx),
          expires = Math.min(
            time + 3600,
            Math.floor(new Date(catalog.expires_at).getTime() / 1000),
            authority.expires("policy"),
          );
        const document: Policy = {
          schemaVersion: 1,
          authorityEpoch: authority.epoch,
          revision: await revision(tx, enrollment.scope_id, "policy", enrollment.id),
          deviceId: enrollment.device_id,
          enrollmentId: enrollment.id,
          platform: enrollment.platform,
          scope: { kind: "machine", machineId: enrollment.machine_id },
          catalogDigest: catalog.payload_digest,
          enabled: selection.enabled,
          disabled: selection.disabled,
          allowedPermissions: selection.allowed_permissions,
          issuedAt: time,
          expiresAt: expires,
        };
        const payload = Buffer.from(JSON.stringify(document));
        parseWire("Policy", payload);
        return storeIntent(tx, authority, {
          id: randomUUID(),
          scope: enrollment.scope_id,
          kind: "policy",
          enrollmentId: enrollment.id,
          revision: document.revision,
          authorizationVersion: scope.version,
          requestHash,
          actor: { issuer: selection.issuer, id: selection.subject },
          predecessor: currentId,
          payload,
          projection: document,
          time,
        });
      });
      let policy = intent;
      if (intent.state !== "published") {
        const signed = await signIntent(authority, intent);
        policy = await db.transaction(async (tx) => {
          const context = await nativeContext(tx, authority, credentialHash);
          if (
            context.enrollment.id !== intent.enrollment_id ||
            hash(JSON.stringify([context.enrollment.id, context.selection.version, context.catalog.id])) !==
              intent.request_hash
          )
            throw new ApiError(409, "native_publication_superseded");
          return finalize(tx, authority, intent, signed.envelope, context.scope.version);
        });
      }
      return db.transaction(async (tx) => {
        const { enrollment, selection, catalog } = await nativeContext(tx, authority, credentialHash);
        if (
          policy.id !== (await head(tx, "policy", enrollment.id)) ||
          policy.request_hash !== hash(JSON.stringify([enrollment.id, selection.version, catalog.id]))
        )
          throw new ApiError(409, "native_policy_changed");
        await tx.query(
          "UPDATE native_nonce_receipts SET response=NULL,state='expired' WHERE enrollment_id=$1 AND state='issued' AND expires_at<=clock_timestamp()",
          [enrollment.id],
        );
        const [prior] = await tx.query<{
          credential_hash: string;
          policy_id: string;
          catalog_id: string;
          state: string;
          response: Buffer;
          expires_at: Date;
        }>(
          "SELECT credential_hash,policy_id,catalog_id,state,response,expires_at FROM native_nonce_receipts WHERE enrollment_id=$1 AND nonce_hash=$2",
          [enrollment.id, nonceHash],
        );
        if (prior) {
          if (
            prior.credential_hash !== credentialHash ||
            prior.policy_id !== policy.id ||
            prior.catalog_id !== catalog.id ||
            prior.state !== "issued" ||
            new Date(prior.expires_at).getTime() <= Date.now()
          )
            throw new ApiError(409, "native_nonce_reuse");
          return Buffer.from(prior.response);
        }
        const [quota] = await tx.query<{ total: number; active: number }>(
          "SELECT count(*)::int AS total,count(*) FILTER(WHERE state='issued')::int AS active FROM native_nonce_receipts WHERE enrollment_id=$1",
          [enrollment.id],
        );
        if (quota!.active >= 64 || quota!.total >= 250000)
          throw new ApiError(429, "native_nonce_budget_exhausted");
        const time = await now(tx),
          expires = Math.min(
            time + 60,
            Math.floor(new Date(policy.expires_at).getTime() / 1000),
            Math.floor(new Date(catalog.expires_at).getTime() / 1000),
            authority.expires("freshness"),
          );
        if (expires <= time) throw new ApiError(409, "native_policy_expired");
        const fresh = Buffer.from(
          JSON.stringify({
            schemaVersion: 1,
            authorityEpoch: authority.epoch,
            deviceId: enrollment.device_id,
            enrollmentId: enrollment.id,
            policyDigest: policy.payload_digest,
            nonce,
            issuedAt: time,
            expiresAt: expires,
          }),
        );
        parseWire("Freshness", fresh);
        const signed = await authority.sign(
          "freshness",
          authority.header("freshness"),
          fresh,
          AbortSignal.timeout(3000),
        );
        const evidenceDigests = [
          ...new Set(
            (catalog.projection as ModuleCatalog).entries.flatMap((entry) =>
              Object.values(entry.platforms).map((value) => value.attestationSha256),
            ),
          ),
        ].sort();
        const attestations: Record<string, string> = {};
        for (const digest of evidenceDigests) {
          const [proof] = await tx.query<{ envelope: Buffer; expires_at: Date }>(
            "SELECT envelope,expires_at FROM native_publisher_evidence WHERE envelope_digest=$1",
            [digest],
          );
          if (!proof || new Date(proof.expires_at).getTime() <= Date.now())
            throw new ApiError(409, "native_publisher_evidence_expired");
          attestations[digest] = Buffer.from(proof.envelope).toString("base64url");
        }
        const response = Buffer.from(
          JSON.stringify({
            policy: Buffer.from(policy.envelope!).toString("base64url"),
            catalog: Buffer.from(catalog.envelope!).toString("base64url"),
            freshness: signed.envelope.toString("base64url"),
            attestations,
          }),
        );
        if (
          !(
            await tx.query(
              "SELECT hash FROM credentials WHERE hash=$1 AND enrollment_id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp() AND clock_timestamp()<to_timestamp($3)",
              [credentialHash, enrollment.id, expires],
            )
          ).length
        )
          throw new ApiError(401, "unauthorized");
        await tx.query(
          "INSERT INTO native_nonce_receipts(enrollment_id,nonce_hash,credential_hash,policy_id,catalog_id,response,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,'issued',to_timestamp($7))",
          [enrollment.id, nonceHash, credentialHash, policy.id, catalog.id, response, expires],
        );
        return response;
      });
    },
  };
}
