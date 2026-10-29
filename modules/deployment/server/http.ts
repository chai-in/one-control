import { randomUUID } from "node:crypto";
import { envelopeSchema } from "@one-control/protocol";
import type { FastifyInstance } from "fastify";
import { audit, type RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { ApiError, verifyRelease } from "../../../apps/control-plane/src/security.js";
export function registerReleasesRoutes(app: FastifyInstance, { db, admin, config }: RouteContext) {
  app.post("/v1/releases", async (request, reply) => {
    const actor = await admin(request, "operator");
    const envelope = envelopeSchema.parse(request.body);
    const manifest = verifyRelease(envelope, config);
    const id = randomUUID();
    await db.transaction(async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        `release:${manifest.packageId}`,
      ]);
      const latest = (
        await tx.query<{ sequence: string }>(
          "SELECT sequence FROM releases WHERE package_id=$1 ORDER BY sequence DESC LIMIT 1",
          [manifest.packageId],
        )
      )[0];
      if (latest && manifest.sequence <= Number(latest.sequence))
        throw new ApiError(409, "release_sequence_not_increasing");
      await tx.query(
        "INSERT INTO releases(id,package_id,sequence,envelope,manifest,created_by) VALUES ($1,$2,$3,$4,$5,$6)",
        [
          id,
          manifest.packageId,
          manifest.sequence,
          JSON.stringify(envelope),
          JSON.stringify(manifest),
          actor.id,
        ],
      );
      await audit(tx, actor.id, "release.registered", id, {
        packageId: manifest.packageId,
        sequence: manifest.sequence,
      });
    });
    return reply.code(201).send({ id, manifest });
  });
  app.get("/v1/releases", async (request) => {
    await admin(request, "viewer");
    return {
      releases: await db.query(
        "SELECT id,package_id,sequence,manifest,created_at FROM releases ORDER BY created_at DESC LIMIT 500",
      ),
    };
  });
}
