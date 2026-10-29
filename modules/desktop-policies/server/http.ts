import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createModuleControl } from "../../../apps/control-plane/src/module-control.js";
import type { RouteContext } from "../../../apps/control-plane/src/routes/context.js";
import { desktopControl, type desktopOperations } from "./control.js";
import { policyId } from "./policy.js";

export function registerDesktopRoutes(app: FastifyInstance, { db, config, admin }: RouteContext) {
  const control = createModuleControl(db, config);
  const base = "/v1/scopes/:id/desktop";
  app.get(base, async (request) => {
    const actor = await admin(request, "viewer");
    const { id } = z.object({ id: z.uuid() }).parse(request.params);
    return control.scopedRoute(actor, id, `GET ${base}`, undefined, (tx, version) =>
      desktopControl.snapshot(tx, id, version),
    );
  });
  app.get(`${base}/policies/:policyId/versions`, async (request) => {
    const actor = await admin(request, "viewer");
    const params = z.object({ id: z.uuid(), policyId }).parse(request.params);
    return control.scopedRoute(actor, params.id, `GET ${base}/policies/:policyId/versions`, undefined, (tx) =>
      desktopControl.versions(tx, params.id, params.policyId),
    );
  });
  app.get(`${base}/devices/:deviceId/policy`, async (request) => {
    const actor = await admin(request, "viewer");
    const params = z.object({ id: z.uuid(), deviceId: z.uuid() }).parse(request.params);
    return control.scopedRoute(actor, params.id, `GET ${base}/devices/:deviceId/policy`, undefined, (tx) =>
      desktopControl.effective(tx, params.id, params.deviceId),
    );
  });
  const writes: Array<["PUT" | "POST" | "DELETE", string, keyof typeof desktopOperations, string?]> = [
    ["PUT", "/policies/:policyId", "save", "policyId"],
    ["DELETE", "/policies/:policyId", "remove", "policyId"],
    ["POST", "/policies/:policyId/clone", "clone", "policyId"],
    ["POST", "/policies/:policyId/rollback", "rollback", "policyId"],
    ["PUT", "/groups/:groupId", "group", "groupId"],
    ["DELETE", "/groups/:groupId", "deleteGroup", "groupId"],
    ["PUT", "/assignments", "assign"],
    ["PUT", "/default-policy", "default"],
    ["POST", "/policies/:policyId/canaries", "stage", "policyId"],
    ["POST", "/canaries/:canaryId/abort", "abort", "canaryId"],
    ["POST", "/canaries/:canaryId/promote", "promote", "canaryId"],
  ];
  for (const [method, suffix, operation, key] of writes)
    app.route({
      method,
      url: `${base}${suffix}`,
      handler: async (request) => {
        const actor = await admin(request, "operator");
        const params = z.record(z.string(), z.string()).parse(request.params);
        const { expectedVersion, ...body } = z
          .object({ expectedVersion: z.string() })
          .passthrough()
          .parse(request.body);
        return control.scopedRoute(
          actor,
          params.id as string,
          `${method} ${base}${suffix}`,
          expectedVersion,
          (tx, version) =>
            desktopControl.mutate(
              tx,
              params.id as string,
              actor,
              operation,
              key ? params[key] : undefined,
              body,
              version,
            ),
        );
      },
    });
}
