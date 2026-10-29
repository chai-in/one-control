import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../../../apps/control-plane/src/module-control.js";
import { audit, type RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { ApiError } from "../../../apps/control-plane/src/security.js";
import { falconResource } from "../../falcon/server/inventory.js";
import { syncFalconPage } from "./data.js";

export function registerFalconDataRoutes(app: FastifyInstance, { db, config, admin }: RouteContext) {
  const control = createModuleControl(db, config);
  app.get("/v1/scopes/:id/falcon-sync", async (request) => {
    const actor = await admin(request, "viewer");
    const { id } = z.object({ id: z.uuid() }).parse(request.params);
    return control.scopedRoute(
      actor,
      id,
      "GET /v1/scopes/:id/falcon-sync",
      undefined,
      async (tx, version) => ({
        version,
        resources: falconResource.options,
        scheduledIntervalSeconds: config.FALCON_SYNC_INTERVAL_SECONDS ?? 0,
        state: await tx.query(
          "SELECT resource,generation,status,count,error_code,filter,updated_at,completed_at,next_due_at FROM falcon_sync_state WHERE scope_id=$1 ORDER BY resource",
          [id],
        ),
      }),
    );
  });
  app.post("/v1/scopes/:id/falcon-sync/:resource", async (request) => {
    const actor = await admin(request, "operator");
    const { id, resource } = z.object({ id: z.uuid(), resource: falconResource }).parse(request.params);
    const { expectedVersion, ...input } = z
      .strictObject({
        expectedVersion: z.string(),
        restart: z.boolean().default(false),
        filter: z.string().max(1024).optional(),
      })
      .parse(request.body);
    return control.scopedRoute(
      actor,
      id,
      "POST /v1/scopes/:id/falcon-sync/:resource",
      expectedVersion,
      async (tx, version) => {
        const result = await syncFalconPage(tx, config, id, resource, input, AbortSignal.timeout(15000));
        await audit(tx, JSON.stringify([actor.issuer, actor.id]), "falcon.sync_page", id, {
          scope: id,
          resource,
          result,
        });
        return { version, result };
      },
    );
  });
  app.get("/v1/scopes/:id/falcon-cache/:resource", async (request) => {
    const actor = await admin(request, "viewer");
    const { id, resource } = z.object({ id: z.uuid(), resource: falconResource }).parse(request.params);
    const { offset, limit } = z
      .strictObject({
        offset: z.coerce.number().int().min(0).default(0),
        limit: z.coerce.number().int().min(1).max(100).default(50),
      })
      .parse(request.query);
    return control.scopedRoute(
      actor,
      id,
      "GET /v1/scopes/:id/falcon-cache/:resource",
      undefined,
      async (tx) => ({
        resource,
        offset,
        limit,
        state:
          (
            await tx.query(
              "SELECT status,filter,completed_at,updated_at,error_code FROM falcon_sync_state WHERE scope_id=$1 AND resource=$2",
              [id, resource],
            )
          )[0] ?? null,
        records: await tx.query(
          "SELECT source_id,payload,observed_at,present FROM falcon_cached_records WHERE scope_id=$1 AND resource=$2 ORDER BY source_id LIMIT $3 OFFSET $4",
          [id, resource, limit, offset],
        ),
      }),
    );
  });
  let timer: ReturnType<typeof setInterval> | undefined;
  let pending: Promise<void> | undefined;
  const stopping = new AbortController();
  app.addHook("onReady", async () => {
    const scope = config.FALCON_MANAGEMENT_SCOPE;
    if (!scope || !config.FALCON_SYNC_INTERVAL_SECONDS) return;
    timer = setInterval(() => {
      if (pending || stopping.signal.aborted) return;
      pending = (async () => {
        for (const resource of falconResource.options) {
          if (stopping.signal.aborted) break;
          await control.service(scope, "background", "falcon.sync", async (tx) => {
            const [state] = await tx.query<{ due: boolean }>(
              "SELECT next_due_at<=clock_timestamp() AS due FROM falcon_sync_state WHERE scope_id=$1 AND resource=$2",
              [scope, resource],
            );
            if (state && !state.due) return;
            await syncFalconPage(
              tx,
              config,
              scope,
              resource,
              {},
              AbortSignal.any([stopping.signal, AbortSignal.timeout(15000)]),
            );
          });
        }
      })()
        .catch((error) => {
          if (
            !(error instanceof ApiError && [403, 503].includes(error.statusCode)) &&
            !stopping.signal.aborted
          )
            app.log.error("Falcon scheduled sync failed; inspect stored progress");
        })
        .finally(() => {
          pending = undefined;
        });
    }, 15000);
    timer.unref();
  });
  app.addHook("onClose", async () => {
    clearInterval(timer);
    stopping.abort();
    await pending;
  });
}
