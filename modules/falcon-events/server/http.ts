import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../../../apps/control-plane/src/module-control.js";
import type { RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { ApiError } from "../../../apps/control-plane/src/security.js";
import { authenticatedFalconEvent, ingestFalconEvent } from "./data.js";
export function registerFalconEventRoutes(app: FastifyInstance, { db, config, admin }: RouteContext) {
  const control = createModuleControl(db, config);
  app.get("/v1/scopes/:id/falcon-events", async (request) => {
    const actor = await admin(request, "viewer");
    const { id } = z.object({ id: z.uuid() }).parse(request.params);
    const { before, aid } = z
      .strictObject({ before: z.iso.datetime().optional(), aid: z.string().max(255).optional() })
      .parse(request.query);
    return control.scopedRoute(
      actor,
      id,
      "GET /v1/scopes/:id/falcon-events",
      undefined,
      async (tx, version) => ({
        version,
        events: await tx.query(
          "SELECT event_id,event_type,aid,payload,occurred_at,received_at FROM falcon_events WHERE scope_id=$1 AND ($2::timestamptz IS NULL OR received_at<$2) AND ($3::text IS NULL OR aid=$3) ORDER BY received_at DESC,event_id LIMIT 100",
          [id, before ?? null, aid ?? null],
        ),
      }),
    );
  });
  app.register(async (webhook) => {
    webhook.removeContentTypeParser("application/json");
    webhook.addContentTypeParser("application/json", { parseAs: "buffer" }, (_request, body, done) =>
      done(null, body),
    );
    webhook.post(
      "/v1/integrations/falcon/webhook",
      { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
      async (request) => {
        const scope = config.FALCON_MANAGEMENT_SCOPE;
        if (!scope) throw new ApiError(503, "integration_scope_unconfigured");
        const event = authenticatedFalconEvent(
          request.body as Buffer,
          request.headers["x-sentry-signature"],
          config.FALCON_WEBHOOK_SECRET,
        );
        return control.service(scope, "route", "POST /v1/integrations/falcon/webhook", (tx) =>
          ingestFalconEvent(tx, scope, event),
        );
      },
    );
  });
}
