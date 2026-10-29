import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../../../apps/control-plane/src/module-control.js";
import type { RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { bearer } from "../../../apps/control-plane/src/security.js";
import { recoveryKeyMetadata } from "./escrow.js";
export function registerRecoveryEscrowRoutes(app: FastifyInstance, { db, config, admin }: RouteContext) {
  const control = createModuleControl(db, config);
  const scope = z.object({ id: z.uuid() });
  app.post("/v1/agent/native-recovery-key", { bodyLimit: 2048 }, async (request) =>
    control.escrowNativeKey(bearer(request), request.body),
  );
  app.get("/v1/scopes/:id/recovery-keys", async (request) => {
    const actor = await admin(request, "viewer"),
      id = scope.parse(request.params).id;
    return control.scopedRoute(actor, id, "GET /v1/scopes/:id/recovery-keys", undefined, (tx, version) =>
      recoveryKeyMetadata(tx, id, version),
    );
  });
  app.post(
    "/v1/scopes/:id/recovery-keys/:keyId/reveal",
    { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
    async (request) => {
      const actor = await admin(request, "operator"),
        { id, keyId } = z.object({ id: z.uuid(), keyId: z.uuid() }).parse(request.params);
      return control.revealRecoveryKey(actor, id, keyId, request.body);
    },
  );
}
