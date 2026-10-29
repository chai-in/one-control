import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ApiError, hash, secret } from "../security.js";
import { audit, type RouteContext } from "./context.js";
export function registerEnrollmentRoutes(app: FastifyInstance, { db, agent, config }: RouteContext) {
  app.post(
    "/v1/agent/enroll",
    { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const input = z
        .object({ token: z.string().min(32).max(100), hostname: z.string().min(1).max(255) })
        .strict()
        .parse(request.body);
      const credential = secret();
      const deviceId = randomUUID();
      await db.transaction(async (tx) => {
        const tokens = await tx.query(
          "UPDATE enrollment_tokens SET used_at=now() WHERE hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING context",
          [hash(input.token)],
        );
        if (!tokens.length) throw new ApiError(401, "invalid_enrollment_token");
        if (config.DEPLOYMENT_STAGE === "poc") {
          await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
            "one-control:poc-enrollment-limit",
          ]);
          const count =
            (
              await tx.query<{ active: number }>(
                "SELECT count(*)::int AS active FROM devices WHERE revoked_at IS NULL",
              )
            )[0]?.active ?? 0;
          if (count >= config.POC_DEVICE_LIMIT) throw new ApiError(409, "poc_device_limit_reached");
        }
        await tx.query("INSERT INTO devices(id,hostname) VALUES ($1,$2)", [deviceId, input.hostname]);
        await tx.query(
          "INSERT INTO credentials(hash,device_id,context,expires_at) VALUES ($1,$2,'system',now()+interval '90 days')",
          [hash(credential), deviceId],
        );
        await audit(tx, `device:${deviceId}`, "device.enrolled", deviceId);
      });
      return reply.code(201).send({ deviceId, credential });
    },
  );
  app.post("/v1/agent/rotate", async (request) => {
    await agent(request);
    throw new ApiError(410, "credential_rotation_upgrade_required");
  });
  app.post("/v1/agent/credentials/rotate", async (request) => {
    const identity = await agent(request);
    const { credentialHash } = z
      .object({ credentialHash: z.string().regex(/^[a-f0-9]{64}$/) })
      .strict()
      .parse(request.body);
    if (credentialHash === identity.hash) throw new ApiError(400, "new_credential_required");
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
      const prior = (
        await tx.query<{ device_id: string; revoked_at: Date | null; expires_at: Date }>(
          "SELECT device_id,revoked_at,expires_at FROM credentials WHERE hash=$1",
          [credentialHash],
        )
      )[0];
      if (prior) {
        if (
          prior.device_id !== identity.device_id ||
          prior.revoked_at ||
          new Date(prior.expires_at).getTime() <= Date.now()
        )
          throw new ApiError(409, "credential_conflict");
        return; // A lost response can be retried without minting another credential or extending overlap.
      }
      await tx.query(
        "INSERT INTO credentials(hash,device_id,context,expires_at) VALUES ($1,$2,'system',now()+interval '90 days')",
        [credentialHash, identity.device_id],
      );
      await tx.query(
        "UPDATE credentials SET expires_at=LEAST(expires_at,now()+interval '5 minutes') WHERE hash=$1",
        [identity.hash],
      );
      await audit(tx, `device:${identity.device_id}`, "credential.rotated", identity.device_id);
    });
    return { ok: true };
  });
  app.post("/v1/agent/heartbeat", async (request) => {
    const identity = await agent(request);
    const { inventory } = z
      .object({ inventory: z.record(z.string(), z.json()).optional() })
      .strict()
      .parse(request.body);
    await db.transaction(async (tx) => {
      const devices = await tx.query("SELECT id FROM devices WHERE id=$1 AND revoked_at IS NULL FOR UPDATE", [
        identity.device_id,
      ]);
      if (!devices.length) throw new ApiError(401, "unauthorized");
      const credentials = await tx.query(
        "SELECT hash FROM credentials WHERE hash=$1 AND device_id=$2 AND context='system' AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
        [identity.hash, identity.device_id],
      );
      if (!credentials.length) throw new ApiError(401, "unauthorized");
      await tx.query("UPDATE devices SET last_seen_at=now() WHERE id=$1", [identity.device_id]);
    });
    return { ok: true, ...(inventory ? { inventoryAccepted: false } : {}) };
  });
}
