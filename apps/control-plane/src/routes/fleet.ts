import { ringSchema } from "@one-control/protocol";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ApiError, hash, secret } from "../security.js";
import { audit, paramsSchema, type RouteContext, requireLegacyDevice } from "./context.js";
export function registerFleetRoutes(app: FastifyInstance, { db, admin, config }: RouteContext) {
  app.get("/v1/me", async (request) => {
    const actor = await admin(request, "viewer");
    return { subject: actor.id, roles: [...actor.roles] };
  });
  app.get("/v1/workspace", async (request) => {
    await admin(request, "viewer");
    return {
      deploymentStage: config.DEPLOYMENT_STAGE,
      deviceLimit: config.DEPLOYMENT_STAGE === "poc" ? config.POC_DEVICE_LIMIT : null,
      serverTime: new Date().toISOString(),
    };
  });
  app.get("/v1/devices", async (request) => {
    const actor = await admin(request, "viewer");
    return {
      devices: await db.query(
        `SELECT d.id,d.hostname,d.ring,d.last_seen_at,d.inventory,COALESCE(d.revoked_at,e.revoked_at) AS revoked_at,e.id AS enrollment_id,e.scope_id AS management_scope_id,s.name AS management_scope_name
        FROM devices d LEFT JOIN LATERAL (SELECT id,scope_id,revoked_at FROM native_enrollments WHERE device_id=d.id ORDER BY (revoked_at IS NULL) DESC,created_at DESC,id LIMIT 1) e ON true
        LEFT JOIN management_scopes s ON s.id=e.scope_id
        WHERE e.id IS NULL OR (s.state='active' AND EXISTS(SELECT 1 FROM scope_grants g WHERE g.scope_id=e.scope_id AND g.issuer=$1 AND g.subject=$2 AND g.permission IN ('owner','view') AND g.revoked_at IS NULL))
        ORDER BY d.created_at DESC,d.id LIMIT 1000`,
        [actor.issuer, actor.id],
      ),
    };
  });
  app.patch("/v1/devices/:id/ring", async (request) => {
    const actor = await admin(request, "operator");
    const { id } = paramsSchema.parse(request.params);
    const { ring } = z.object({ ring: ringSchema }).strict().parse(request.body);
    if (config.DEPLOYMENT_STAGE === "poc" && ring !== "canary") throw new ApiError(403, "poc_canary_only");
    await db.transaction(async (tx) => {
      if (
        !(await tx.query("SELECT id FROM devices WHERE id=$1 AND revoked_at IS NULL FOR UPDATE", [id])).length
      )
        throw new ApiError(404, "device_not_found");
      await requireLegacyDevice(tx, id);
      if (
        (
          await tx.query(
            "SELECT id FROM jobs WHERE device_id=$1 AND state IN ('awaiting_approval','queued','leased','indeterminate') LIMIT 1",
            [id],
          )
        ).length
      )
        throw new ApiError(409, "device_has_unfinished_jobs");
      if (
        !(
          await tx.query("UPDATE devices SET ring=$1 WHERE id=$2 AND revoked_at IS NULL RETURNING id", [
            ring,
            id,
          ])
        ).length
      )
        throw new ApiError(404, "device_not_found");
      await audit(tx, actor.id, "device.ring_changed", id, { ring });
    });
    return { ok: true };
  });
  app.post("/v1/devices/:id/revoke", async (request) => {
    const actor = await admin(request, "operator");
    const { id } = paramsSchema.parse(request.params);
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM devices WHERE id=$1 FOR UPDATE", [id]);
      await requireLegacyDevice(tx, id);
      if (
        !(
          await tx.query(
            "UPDATE devices SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL RETURNING id",
            [id],
          )
        ).length
      )
        throw new ApiError(404, "device_not_found");
      await tx.query("UPDATE credentials SET revoked_at=now() WHERE device_id=$1", [id]);
      await tx.query(
        "UPDATE jobs SET state='cancelled',finished_at=now() WHERE device_id=$1 AND state IN ('queued','awaiting_approval')",
        [id],
      );
      await tx.query(
        "UPDATE jobs SET state='indeterminate',lease_hash=NULL,lease_expires_at=NULL,finished_at=now() WHERE device_id=$1 AND state='leased'",
        [id],
      );
      await audit(tx, actor.id, "device.revoked", id);
    });
    return { ok: true };
  });
  app.post("/v1/enrollment-tokens", async (request, reply) => {
    const actor = await admin(request, "operator");
    z.object({}).strict().parse(request.body);
    const token = secret();
    const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();
    await db.transaction(async (tx) => {
      await tx.query(
        "INSERT INTO enrollment_tokens(hash,context,expires_at,created_by) VALUES ($1,'system',$2,$3)",
        [hash(token), expiresAt, actor.id],
      );
      await audit(tx, actor.id, "enrollment.created", "new-device", { expiresAt });
    });
    return reply.code(201).send({ token, expiresAt });
  });
}
