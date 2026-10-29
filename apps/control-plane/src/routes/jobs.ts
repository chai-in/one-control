import { randomUUID } from "node:crypto";
import {
  type BatchReview,
  type Command,
  commandContext,
  createJobSchema,
  envelopeSchema,
  isMutation,
} from "@one-control/protocol";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { TransactionQuery } from "../database.js";
import { createModuleControl } from "../module-control.js";
import { ApiError, hash, verifyRelease } from "../security.js";
import { commandModules } from "../server-modules.js";
import { audit, paramsSchema, type RouteContext } from "./context.js";

async function readBatch(tx: TransactionQuery, id: string): Promise<BatchReview> {
  const batch = (
    await tx.query<{
      id: string;
      created_by: string;
      created_at: Date;
      approved_by: string | null;
      command: Command;
      ring: BatchReview["ring"];
    }>("SELECT id,created_by,created_at,approved_by,command,ring FROM batches WHERE id=$1", [id])
  )[0];
  if (!batch) throw new ApiError(404, "batch_not_found");
  const jobs = await tx.query<{
    device_id: string;
    hostname: string;
    starts_at: Date;
    ends_at: Date;
    state: BatchReview["targets"][number]["state"];
  }>(
    "SELECT j.device_id,d.hostname,j.starts_at,j.ends_at,j.state FROM jobs j JOIN devices d ON d.id=j.device_id WHERE batch_id=$1 ORDER BY j.device_id",
    [id],
  );
  const release =
    batch.command.kind === "package.install"
      ? ((
          await tx.query<{ manifest: BatchReview["release"] }>("SELECT manifest FROM releases WHERE id=$1", [
            batch.command.releaseId,
          ])
        )[0]?.manifest ?? null)
      : null;
  const targets = jobs.map((j) => ({
    deviceId: j.device_id,
    hostname: j.hostname,
    startsAt: new Date(j.starts_at).toISOString(),
    endsAt: new Date(j.ends_at).toISOString(),
    state: j.state,
  }));
  const immutable = {
    id,
    createdBy: batch.created_by,
    command: batch.command,
    ring: batch.ring,
    targets: targets.map(({ deviceId, startsAt, endsAt }) => ({ deviceId, startsAt, endsAt })),
    release,
  };
  return {
    ...immutable,
    createdAt: new Date(batch.created_at).toISOString(),
    approvedBy: batch.approved_by,
    targets,
    reviewDigest: hash(JSON.stringify(immutable)),
  };
}
export function registerJobsRoutes(app: FastifyInstance, { db, admin, config }: RouteContext) {
  const modules = createModuleControl(db, config);
  app.get("/v1/batches/:id", async (request) => {
    const actor = await admin(request, "viewer");
    const { id } = paramsSchema.parse(request.params);
    const targets = await db.query<{ device_id: string }>(
      "SELECT device_id FROM jobs WHERE batch_id=$1 ORDER BY device_id",
      [id],
    );
    return modules.history(
      actor,
      targets.map((row) => row.device_id),
      "view",
      (tx) => readBatch(tx, id),
    );
  });
  app.post("/v1/batches", async (request, reply) => {
    const actor = await admin(request, "operator");
    const input = createJobSchema.parse(request.body);
    if (config.DEPLOYMENT_STAGE === "poc" && input.ring !== "canary")
      throw new ApiError(403, "poc_canary_only");
    const key = z
      .string()
      .regex(/^[A-Za-z0-9_-]{16,128}$/)
      .parse(request.headers["idempotency-key"]);
    const requestHash = hash(JSON.stringify(input));
    const identityKey = JSON.stringify([actor.issuer, actor.id]);
    if (Date.parse(input.endsAt) <= Date.now()) throw new ApiError(400, "maintenance_window_expired");
    const response = await modules.command(actor, input.targets, input.command.kind, "create", async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`${identityKey}:${key}`]);
      const prior = (
        await tx.query<{ request_hash: string; response: { batchId: string; jobIds: string[] } }>(
          "SELECT request_hash,response FROM idempotency_keys WHERE actor=$1 AND key=$2",
          [identityKey, key],
        )
      )[0];
      if (prior) {
        if (prior.request_hash !== requestHash) throw new ApiError(409, "idempotency_conflict");
        return prior.response;
      }
      const targets = await tx.query<{ id: string; inventory: Record<string, unknown> | null }>(
        "SELECT id,inventory FROM devices WHERE id=ANY($1::uuid[]) AND ring=$2 AND revoked_at IS NULL ORDER BY id FOR UPDATE",
        [input.targets, input.ring],
      );
      if (targets.length !== input.targets.length) throw new ApiError(400, "invalid_targets_or_ring");
      if (input.command.kind === "package.install") {
        const release = (
          await tx.query<{ envelope: unknown }>("SELECT envelope FROM releases WHERE id=$1", [
            input.command.releaseId,
          ])
        )[0];
        if (!release) throw new ApiError(404, "release_not_found");
        const manifest = verifyRelease(envelopeSchema.parse(release.envelope), config);
        if (
          manifest.packageId === "one-control-agent" &&
          targets.some((target) => target.inventory?.agentRecoveryReady !== true)
        )
          throw new ApiError(409, "agent_recovery_unavailable");
      }
      const batchId = randomUUID();
      const jobIds: string[] = [];
      await tx.query("INSERT INTO batches(id,created_by,command,ring) VALUES ($1,$2,$3,$4)", [
        batchId,
        actor.id,
        JSON.stringify(input.command),
        input.ring,
      ]);
      for (const target of input.targets) {
        const id = randomUUID();
        jobIds.push(id);
        await tx.query(
          "INSERT INTO jobs(id,batch_id,device_id,context,kind,command,state,starts_at,ends_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
          [
            id,
            batchId,
            target,
            commandContext(input.command),
            input.command.kind,
            JSON.stringify(input.command),
            isMutation(input.command) ? "awaiting_approval" : "queued",
            input.startsAt,
            input.endsAt,
          ],
        );
        await tx.query(
          "INSERT INTO native_job_admissions(job_id,enrollment_id,scope_id,module_id,creator_issuer,creator_subject) SELECT $1,id,scope_id,$3,$4,$5 FROM native_enrollments WHERE device_id=$2 AND revoked_at IS NULL",
          [id, target, commandModules[input.command.kind], actor.issuer, actor.id],
        );
      }
      const result = { batchId, jobIds };
      await tx.query("INSERT INTO idempotency_keys(actor,key,request_hash,response) VALUES ($1,$2,$3,$4)", [
        identityKey,
        key,
        requestHash,
        JSON.stringify(result),
      ]);
      await audit(tx, actor.id, "batch.created", batchId, {
        kind: input.command.kind,
        targets: input.targets,
        ring: input.ring,
        agreementPolicy: "organisation_default",
      });
      return result;
    });
    return reply.code(201).send(response);
  });
  app.post("/v1/batches/:id/approve", async (request) => {
    const actor = await admin(request, "approver");
    const { id } = paramsSchema.parse(request.params);
    const { reviewDigest } = z
      .object({ reviewDigest: z.string().regex(/^[a-f0-9]{64}$/) })
      .strict()
      .parse(request.body);
    const [locator] = await db.query<{ command: Command }>("SELECT command FROM batches WHERE id=$1", [id]);
    if (!locator) throw new ApiError(404, "batch_not_found");
    const targetLocators = await db.query<{ device_id: string }>(
      "SELECT device_id FROM jobs WHERE batch_id=$1 ORDER BY device_id",
      [id],
    );
    await modules.command(
      actor,
      targetLocators.map((target) => target.device_id),
      locator.command.kind,
      "approve",
      async (tx) => {
        const batch = (
          await tx.query<{ created_by: string; command: Command; ring: string; approved_by: string | null }>(
            "SELECT created_by,command,ring,approved_by FROM batches WHERE id=$1 FOR UPDATE",
            [id],
          )
        )[0];
        if (!batch) throw new ApiError(404, "batch_not_found");
        if (config.DEPLOYMENT_STAGE === "poc" && batch.ring !== "canary")
          throw new ApiError(403, "poc_canary_only");
        if (batch.created_by === actor.id) throw new ApiError(403, "separate_approver_required");
        if (batch.approved_by) throw new ApiError(409, "already_approved");
        const review = await readBatch(tx, id);
        if (review.reviewDigest !== reviewDigest) throw new ApiError(409, "batch_review_changed");
        if (
          review.targets.some(
            (target) => target.state !== "awaiting_approval" || Date.parse(target.endsAt) <= Date.now(),
          )
        )
          throw new ApiError(409, "batch_not_approvable");
        if (isMutation(batch.command) && batch.ring !== "canary") {
          const previousRing = batch.ring === "pilot" ? "canary" : "pilot";
          const passed = await tx.query(
            `SELECT b.id FROM batches b WHERE b.command=$1::jsonb AND b.ring=$2 AND b.approved_by IS NOT NULL
          AND EXISTS(SELECT 1 FROM jobs j WHERE j.batch_id=b.id)
          AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.batch_id=b.id AND j.state<>'succeeded') LIMIT 1`,
            [JSON.stringify(batch.command), previousRing],
          );
          if (!passed.length) throw new ApiError(409, "previous_ring_not_successful");
        }
        const jobs = await tx.query(
          "UPDATE jobs SET state='queued' WHERE batch_id=$1 AND state='awaiting_approval' AND ends_at>now() RETURNING id",
          [id],
        );
        if (jobs.length !== review.targets.length || !jobs.length)
          throw new ApiError(409, "batch_not_approvable");
        await tx.query("UPDATE batches SET approved_by=$1 WHERE id=$2", [actor.id, id]);
        const admissions = await tx.query(
          "UPDATE native_job_admissions SET approver_issuer=$2,approver_subject=$3 WHERE job_id IN (SELECT id FROM jobs WHERE batch_id=$1) RETURNING job_id",
          [id, actor.issuer, actor.id],
        );
        if (admissions.length !== review.targets.length)
          throw new ApiError(409, "native_job_admission_missing");
        await audit(tx, actor.id, "batch.approved", id, { reviewDigest, targetCount: review.targets.length });
      },
    );
    return { ok: true };
  });
  app.post("/v1/batches/:id/cancel", async (request) => {
    const actor = await admin(request, "operator");
    const { id } = paramsSchema.parse(request.params);
    const targets = await db.query<{ device_id: string }>(
      "SELECT device_id FROM jobs WHERE batch_id=$1 ORDER BY device_id",
      [id],
    );
    await modules.history(
      actor,
      targets.map((row) => row.device_id),
      "command",
      async (tx) => {
        if (!(await tx.query("SELECT id FROM batches WHERE id=$1 FOR UPDATE", [id])).length)
          throw new ApiError(404, "batch_not_found");
        await tx.query(
          "UPDATE jobs SET state='cancelled',finished_at=now() WHERE batch_id=$1 AND state IN ('queued','awaiting_approval')",
          [id],
        );
        await audit(tx, actor.id, "batch.cancelled_pending", id);
      },
    );
    return { ok: true };
  });
  app.get("/v1/jobs", async (request) => {
    const actor = await admin(request, "viewer");
    return {
      jobs: await db.query(
        "SELECT j.id,j.batch_id,j.device_id,j.context,j.kind,j.command,j.state,j.starts_at,j.ends_at,j.attempt,j.result,j.created_at,j.finished_at,b.created_by FROM jobs j JOIN batches b ON b.id=j.batch_id WHERE NOT EXISTS(SELECT 1 FROM native_enrollments e WHERE e.device_id=j.device_id AND NOT EXISTS(SELECT 1 FROM scope_grants g JOIN management_scopes s ON s.id=g.scope_id WHERE g.scope_id=e.scope_id AND g.issuer=$1 AND g.subject=$2 AND g.permission IN ('owner','view') AND g.revoked_at IS NULL AND s.state='active')) ORDER BY j.created_at DESC,j.id LIMIT 1000",
        [actor.issuer, actor.id],
      ),
    };
  });
  app.post("/v1/jobs/:id/reconcile", async (request) => {
    const actor = await admin(request, "operator");
    const { id } = paramsSchema.parse(request.params);
    const input = z
      .object({ state: z.enum(["succeeded", "failed"]), evidence: z.string().min(20).max(2000) })
      .strict()
      .parse(request.body);
    const [locator] = await db.query<{ device_id: string }>("SELECT device_id FROM jobs WHERE id=$1", [id]);
    if (!locator) throw new ApiError(404, "job_not_found");
    await modules.history(actor, [locator.device_id], "command", async (tx) => {
      const job = (await tx.query<{ device_id: string }>("SELECT device_id FROM jobs WHERE id=$1", [id]))[0];
      if (!job) throw new ApiError(404, "job_not_found");
      await tx.query("SELECT id FROM devices WHERE id=$1 FOR UPDATE", [job.device_id]);
      if (
        !(
          await tx.query(
            "UPDATE jobs SET state=$1,result=$2,finished_at=now() WHERE id=$3 AND state='indeterminate' RETURNING id",
            [input.state, JSON.stringify({ reconciledBy: actor.id, evidence: input.evidence }), id],
          )
        ).length
      )
        throw new ApiError(409, "job_not_indeterminate");
      await audit(tx, actor.id, "job.reconciled", id, input);
    });
    return { ok: true };
  });
  app.get("/v1/audit", async (request) => {
    await admin(request, "viewer");
    const { after, direction } = z
      .object({
        after: z.coerce.number().int().min(0).default(0),
        direction: z.enum(["forward", "latest"]).default("forward"),
      })
      .parse(request.query);
    return {
      events: await db.query(
        `SELECT sequence,actor,action,subject,detail,created_at FROM audit_events a WHERE sequence>$1 AND action NOT LIKE 'scope.%' AND action NOT LIKE 'native.%' AND NOT EXISTS(SELECT 1 FROM jobs j JOIN native_enrollments e ON e.device_id=j.device_id WHERE j.id::text=a.subject OR j.batch_id::text=a.subject) ORDER BY sequence ${direction === "latest" ? "DESC" : "ASC"} LIMIT 500`,
        [after],
      ),
    };
  });
}
