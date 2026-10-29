import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../../../apps/control-plane/src/module-control.js";
import type { RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { bearer } from "../../../apps/control-plane/src/security.js";

export function registerNativePublicationRoutes(app: FastifyInstance, { db, config, admin }: RouteContext) {
  const control = createModuleControl(db, config);
  const scope = z.object({ id: z.uuid() });
  app.post("/v1/authority/native-custody/activate", async (request) => {
    const actor = await admin(request, "operator");
    z.strictObject({}).parse(request.body);
    return control.activateNativeCustody(actor);
  });
  app.get("/v1/scopes/:id/native-modules", async (request) =>
    control.nativeStatus(await admin(request, "viewer"), scope.parse(request.params).id),
  );
  app.post("/v1/scopes/:id/native-modules/catalog", { bodyLimit: 16 * 1024 * 1024 }, async (request) =>
    control.publishNativeCatalog(
      await admin(request, "operator"),
      scope.parse(request.params).id,
      request.body,
    ),
  );
  app.put("/v1/scopes/:id/native-modules/selection", async (request) =>
    control.configureNativeSelection(
      await admin(request, "operator"),
      scope.parse(request.params).id,
      request.body,
    ),
  );
  app.post("/v1/agent/native-configuration", async (request, reply) => {
    const bytes = await control.issueNativeConfiguration(bearer(request), request.body);
    return reply.type("application/json").send(bytes);
  });
}
