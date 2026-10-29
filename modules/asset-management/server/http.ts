import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../../../apps/control-plane/src/module-control.js";
import type { RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { assetControl, linkSource } from "./control.js";
import { assetRoutes } from "./routes.js";

export function registerAssetRoutes(app: FastifyInstance, { db, config, admin }: RouteContext) {
  const control = createModuleControl(db, config);
  for (const entry of assetRoutes) {
    const [method, url] = entry.split(" ") as ["GET" | "PUT" | "POST" | "DELETE", string];
    app.route({
      method,
      url,
      handler: async (request) => {
        const actor = await admin(request, method === "GET" ? "viewer" : "operator");
        const params = z
          .object({
            id: z.uuid(),
            assetId: z.uuid().optional(),
            personId: z.uuid().optional(),
            source: linkSource.optional(),
          })
          .parse(request.params);
        const body =
          method === "GET"
            ? undefined
            : z.object({ expectedVersion: z.string() }).passthrough().parse(request.body);
        const { expectedVersion, ...input } = body ?? {};
        return control.scopedRoute(actor, params.id, entry, expectedVersion, async (tx, version) => {
          if (method === "GET") return assetControl.snapshot(tx, params.id, version);
          let result: unknown;
          if (params.personId) {
            if (method === "POST") {
              z.strictObject({}).parse(input);
              result = await assetControl.offboard(tx, params.id, params.personId, actor);
            } else result = await assetControl.savePerson(tx, params.id, params.personId, input, actor);
          } else if (params.assetId && params.source) {
            if (method === "DELETE") {
              z.strictObject({}).parse(input);
              result = await assetControl.unlink(tx, params.id, params.assetId, params.source, actor);
            } else
              result = await assetControl.link(tx, params.id, params.assetId, params.source, input, actor);
          } else if (params.assetId) {
            if (method === "DELETE") {
              z.strictObject({}).parse(input);
              result = await assetControl.removeAsset(tx, params.id, params.assetId, actor);
            } else result = await assetControl.saveAsset(tx, params.id, params.assetId, input, actor);
          }
          return { version, result };
        });
      },
    });
  }
}
