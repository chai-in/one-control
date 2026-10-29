import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../../../apps/control-plane/src/module-control.js";
import type { RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { ApiError } from "../../../apps/control-plane/src/security.js";
import { EmaClient } from "./client.js";

export function registerEmaRoutes(app: FastifyInstance, { db, config, admin }: RouteContext) {
  const modules = createModuleControl(db, config);
  app.get("/v1/integrations/ema/endpoints", async (request) => {
    const actor = await admin(request, "viewer");
    const { hostname, scopeId } = z
      .object({ hostname: z.string().trim().min(1).max(256).optional(), scopeId: z.uuid() })
      .strict()
      .parse(request.query);
    return modules.integration(actor, scopeId, "GET /v1/integrations/ema/endpoints", async (signal) => {
      const ema = new EmaClient(config, (input, init) =>
        fetch(input, { ...init, signal: AbortSignal.any([signal, init?.signal ?? signal]) }),
      );
      if (!ema.configured) return { configured: false, endpoints: [] };
      try {
        return {
          configured: true,
          collectedAt: new Date().toISOString(),
          endpoints: await ema.endpoints(hostname),
        };
      } catch {
        throw new ApiError(503, "ema_unavailable");
      }
    });
  });
}
