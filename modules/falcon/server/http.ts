import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../../../apps/control-plane/src/module-control.js";
import type { RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { ApiError } from "../../../apps/control-plane/src/security.js";
import { FalconInventory, falconPageQuery, falconResource } from "./inventory.js";

export function registerFalconInventoryRoutes(app: FastifyInstance, { db, config, admin }: RouteContext) {
  const control = createModuleControl(db, config);
  const path = "/v1/integrations/falcon/inventory/:resource";
  app.get(path, async (request) => {
    const actor = await admin(request, "viewer");
    const { resource } = z.object({ resource: falconResource }).parse(request.params);
    const input = falconPageQuery.parse(request.query);
    return control.integration(actor, input.scopeId, `GET ${path}`, async (signal) => {
      try {
        return await new FalconInventory(config, signal).page(resource, input);
      } catch (error) {
        if (error instanceof ApiError) throw error;
        throw new ApiError(503, "falcon_unavailable");
      }
    });
  });
  for (const operation of ["detail", "assessment"] as const)
    app.get(`/v1/integrations/falcon/hosts/:aid/${operation}`, async (request) => {
      const actor = await admin(request, "viewer");
      const { aid } = z.object({ aid: z.string().regex(/^[a-fA-F0-9]{32}$/) }).parse(request.params);
      const { scopeId } = z.strictObject({ scopeId: z.uuid() }).parse(request.query);
      return control.integration(
        actor,
        scopeId,
        `GET /v1/integrations/falcon/hosts/:aid/${operation}`,
        async (signal) => {
          try {
            const client = new FalconInventory(config, signal);
            return {
              collectedAt: new Date().toISOString(),
              data: operation === "detail" ? await client.host(aid) : await client.assessment(aid),
            };
          } catch (error) {
            if (error instanceof ApiError) throw error;
            throw new ApiError(503, "falcon_unavailable");
          }
        },
      );
    });
}
