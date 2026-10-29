import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../module-control.js";
import { bearer } from "../security.js";
import { paramsSchema, type RouteContext } from "./context.js";

export function registerModuleRoutes(app: FastifyInstance, { db, config, admin }: RouteContext) {
  const control = createModuleControl(db, config);
  app.patch("/v1/scopes/:id/native-enrollments/:enrollmentId/ring", async (request) => {
    const actor = await admin(request, "operator"),
      { id, enrollmentId } = z.object({ id: z.uuid(), enrollmentId: z.uuid() }).parse(request.params);
    return control.nativeRing(actor, id, enrollmentId, request.body);
  });
  app.get("/v1/scopes", async (request) => control.listScopes(await admin(request, "viewer")));
  app.get("/v1/scopes/:id/audit", async (request) =>
    control.scopeAudit(await admin(request, "viewer"), paramsSchema.parse(request.params).id),
  );
  app.get("/v1/agent/native-enrollment", async (request) => control.enrollment(bearer(request)));
  app.put("/v1/scopes/:id/permissions", async (request) =>
    control.setPermissionCeiling(
      await admin(request, "operator"),
      paramsSchema.parse(request.params).id,
      request.body,
    ),
  );
  app.put("/v1/scopes/:id/server-modules", async (request) =>
    control.configureServerModules(
      await admin(request, "operator"),
      paramsSchema.parse(request.params).id,
      request.body,
    ),
  );
  app.post("/v1/scopes", async (request, reply) =>
    reply.code(201).send(await control.createScope(await admin(request, "operator"), request.body)),
  );
  app.get("/v1/scopes/:id/modules", async (request) =>
    control.readScope(await admin(request, "viewer"), paramsSchema.parse(request.params).id),
  );
  app.put("/v1/scopes/:id/grants", async (request) =>
    control.changeGrant(
      await admin(request, "operator"),
      paramsSchema.parse(request.params).id,
      request.body,
    ),
  );
  app.get("/v1/scopes/:id/grants", async (request) =>
    control.readGrants(await admin(request, "operator"), paramsSchema.parse(request.params).id),
  );
  app.post("/v1/scopes/:id/native-invitations", async (request, reply) =>
    reply
      .code(201)
      .send(
        await control.invite(
          await admin(request, "operator"),
          paramsSchema.parse(request.params).id,
          request.body,
        ),
      ),
  );
  app.post(
    "/v1/agent/native-enroll",
    { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } },
    async (request, reply) =>
      reply
        .code(201)
        .send(
          await control.redeem(request.body, request.headers.authorization ? bearer(request) : undefined),
        ),
  );
  app.post("/v1/agent/native-credentials/rotate", async (request) =>
    control.rotate(bearer(request), request.body),
  );
  app.post("/v1/scopes/:id/native-enrollments/:enrollmentId/revoke", async (request) => {
    const actor = await admin(request, "operator");
    const { id, enrollmentId } = z
      .strictObject({ id: z.uuid(), enrollmentId: z.uuid() })
      .parse(request.params);
    z.strictObject({}).parse(request.body);
    return control.revokeEnrollment(actor, id, enrollmentId);
  });
}
