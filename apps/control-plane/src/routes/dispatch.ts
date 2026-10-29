import { isDeepStrictEqual } from "node:util";
import { type Command, envelopeSchema, type Lease } from "@one-control/protocol";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { reconcileDeviceJobs } from "../coordinator.js";
import { ApiError, hash, secret, verifyRelease } from "../security.js";
import { audit, paramsSchema, type RouteContext, reportSchema } from "./context.js";
export function registerDispatchRoutes(app: FastifyInstance, { db, agent, config }: RouteContext) {
  app.post("/v1/agent/claim", async (request) => {
    const identity = await agent(request);
    z.object({}).strict().parse(request.body);
    const lease = await db.transaction(async (tx): Promise<Lease | null> => {
      const device = (
        await tx.query<{ id: string; ring: string; inventory: unknown }>(
          "SELECT id,ring,inventory FROM devices WHERE id=$1 AND revoked_at IS NULL FOR UPDATE",
          [identity.device_id],
        )
      )[0];
      if (!device) throw new ApiError(401, "unauthorized");
      if (
        !(
          await tx.query(
            "SELECT hash FROM credentials WHERE hash=$1 AND device_id=$2 AND context='system' AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
            [identity.hash, identity.device_id],
          )
        ).length
      )
        throw new ApiError(401, "unauthorized");
      // Changing deployment stage never revokes credentials or interrupts a running installer.
      // It does prevent any new dispatch outside the explicitly limited proof-of-concept ring.
      if (config.DEPLOYMENT_STAGE === "poc" && device.ring !== "canary") return null;
      await reconcileDeviceJobs(tx, identity.device_id);
      // Never dispatch a new operation while an earlier installer may still be running.
      if (
        (
          await tx.query("SELECT id FROM jobs WHERE device_id=$1 AND state='indeterminate'", [
            identity.device_id,
          ])
        ).length
      )
        return null;
      if (
        (await tx.query("SELECT id FROM jobs WHERE device_id=$1 AND state='leased'", [identity.device_id]))
          .length
      )
        return null;
      const job = (
        await tx.query<{ id: string; command: Command; ends_at: Date }>(
          "SELECT id,command,ends_at FROM jobs WHERE device_id=$1 AND state='queued' AND starts_at<=now() AND ends_at>now() AND attempt<3 ORDER BY created_at,id LIMIT 1 FOR UPDATE",
          [identity.device_id],
        )
      )[0];
      if (!job) return null;
      let release = null;
      if (job.command.kind === "package.install") {
        const row = (
          await tx.query<{ envelope: unknown }>("SELECT envelope FROM releases WHERE id=$1", [
            job.command.releaseId,
          ])
        )[0];
        if (!row) throw new ApiError(409, "release_not_found");
        release = envelopeSchema.parse(row.envelope);
        verifyRelease(release, config);
      }
      const leaseToken = secret();
      const leaseExpiresAt = new Date(Date.now() + 120_000).toISOString();
      await tx.query(
        "UPDATE jobs SET state='leased',attempt=attempt+1,lease_hash=$1,lease_expires_at=$2 WHERE id=$3",
        [hash(leaseToken), leaseExpiresAt, job.id],
      );
      await audit(tx, `device:${identity.device_id}`, "job.leased", job.id);
      return {
        id: job.id,
        leaseToken,
        leaseExpiresAt,
        command: job.command,
        release,
        endsAt: new Date(job.ends_at).toISOString(),
      };
    });
    return { lease };
  });
  app.post("/v1/agent/jobs/:id/renew", async (request) => {
    const identity = await agent(request);
    const { id } = paramsSchema.parse(request.params);
    const { leaseToken } = z
      .object({ leaseToken: z.string().min(32).max(100) })
      .strict()
      .parse(request.body);
    await db.transaction(async (tx) => {
      if (
        !(
          await tx.query("SELECT id FROM devices WHERE id=$1 AND revoked_at IS NULL FOR UPDATE", [
            identity.device_id,
          ])
        ).length
      )
        throw new ApiError(401, "unauthorized");
      if (
        !(
          await tx.query(
            "SELECT hash FROM credentials WHERE hash=$1 AND device_id=$2 AND context='system' AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
            [identity.hash, identity.device_id],
          )
        ).length
      )
        throw new ApiError(401, "unauthorized");
      const rows = await tx.query(
        "UPDATE jobs SET lease_expires_at=clock_timestamp()+interval '120 seconds' WHERE id=$1 AND device_id=$2 AND state='leased' AND lease_hash=$3 AND lease_expires_at>clock_timestamp() RETURNING lease_expires_at",
        [id, identity.device_id, hash(leaseToken)],
      );
      if (!rows.length) throw new ApiError(409, "lease_lost");
    });
    return { ok: true };
  });
  app.post("/v1/agent/jobs/:id/report", async (request) => {
    const identity = await agent(request);
    const { id } = paramsSchema.parse(request.params);
    const input = reportSchema.parse(request.body);
    await db.transaction(async (tx) => {
      if (
        !(
          await tx.query("SELECT id FROM devices WHERE id=$1 AND revoked_at IS NULL FOR UPDATE", [
            identity.device_id,
          ])
        ).length
      )
        throw new ApiError(401, "unauthorized");
      if (
        !(
          await tx.query(
            "SELECT hash FROM credentials WHERE hash=$1 AND device_id=$2 AND context='system' AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
            [identity.hash, identity.device_id],
          )
        ).length
      )
        throw new ApiError(401, "unauthorized");
      const job = (
        await tx.query<{ state: string; result: unknown; command: Command }>(
          "SELECT state,result,command FROM jobs WHERE id=$1 AND device_id=$2 FOR UPDATE",
          [id, identity.device_id],
        )
      )[0];
      if (!job) throw new ApiError(404, "job_not_found");
      // Identical terminal receipts are safe to acknowledge after a network retry.
      if (job.state === input.state && isDeepStrictEqual(job.result, input.result)) return;
      if (
        !(
          await tx.query(
            "UPDATE jobs SET state=$1,result=$2,lease_hash=NULL,lease_expires_at=NULL,finished_at=now() WHERE id=$3 AND device_id=$4 AND state='leased' AND lease_hash=$5 AND lease_expires_at>now() RETURNING id",
            [input.state, JSON.stringify(input.result), id, identity.device_id, hash(input.leaseToken)],
          )
        ).length
      )
        throw new ApiError(409, "lease_lost");
      // Legacy terminal receipts preserve evidence but cannot update optional inventory.
      await audit(tx, `device:${identity.device_id}`, "job.reported", id, { state: input.state });
    });
    return { ok: true };
  });
}
