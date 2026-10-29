import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../../../apps/control-plane/src/module-control.js";
import type { RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { bearer } from "../../../apps/control-plane/src/security.js";
import { nativeObservationSnapshot } from "./observations.js";
export function registerNativeObservationRoutes(app: FastifyInstance, { db, config, admin }: RouteContext) {
  const control = createModuleControl(db, config);
  const scope = z.object({ id: z.uuid() });
  app.get("/v1/agent/native-report-state", async (request) => control.nativeReportState(bearer(request)));
  app.post("/v1/agent/native-report", { bodyLimit: 16384 }, async (request) =>
    control.nativeReport(bearer(request), request.body),
  );
  app.get("/v1/scopes/:id/native-observations", async (request) => {
    const actor = await admin(request, "viewer"),
      id = scope.parse(request.params).id;
    return control.scopedRoute(
      actor,
      id,
      "GET /v1/scopes/:id/native-observations",
      undefined,
      (tx, version) => nativeObservationSnapshot(tx, id, version),
    );
  });
}
