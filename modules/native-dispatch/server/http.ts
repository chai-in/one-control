import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../../../apps/control-plane/src/module-control.js";
import type { RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { bearer } from "../../../apps/control-plane/src/security.js";
export function registerNativeJobRoutes(app: FastifyInstance, { db, config }: RouteContext) {
  const control = createModuleControl(db, config);
  const scope = z.object({ id: z.uuid() });
  app.post("/v1/agent/native-claim", async (request) =>
    control.claimNativeJob(bearer(request), request.body),
  );
  app.get("/v1/agent/native-claims/:id", async (request) =>
    control.readNativeClaim(bearer(request), scope.parse(request.params).id),
  );
  app.post("/v1/agent/native-jobs/:id/renew", async (request) =>
    control.renewNativeJob(bearer(request), scope.parse(request.params).id, request.body),
  );
  app.post("/v1/agent/native-jobs/:id/report", { bodyLimit: 262144 }, async (request) =>
    control.reportNativeJob(bearer(request), scope.parse(request.params).id, request.body),
  );
}
