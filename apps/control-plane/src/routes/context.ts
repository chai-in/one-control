import type { FastifyRequest } from "fastify";
import { z } from "zod";
import type { Config } from "../config.js";
import type { Database, TransactionQuery } from "../database.js";
import type { administratorAuth } from "../security.js";
import { ApiError } from "../security.js";

/** Call only after locking the device. Scoped native devices cannot enter legacy management. */
export async function requireLegacyDevice(tx: TransactionQuery, id: string) {
  if ((await tx.query("SELECT id FROM native_enrollments WHERE device_id=$1 LIMIT 1", [id])).length)
    throw new ApiError(409, "native_module_authority_required");
}
export const paramsSchema = z.object({ id: z.uuid() });
export const reportSchema = z
  .object({
    leaseToken: z.string().min(32).max(100),
    state: z.enum(["succeeded", "failed", "indeterminate"]),
    result: z.record(z.string(), z.json()),
  })
  .strict();
export async function audit(
  tx: TransactionQuery,
  actor: string,
  action: string,
  subject: string,
  detail: unknown = {},
) {
  await tx.query("INSERT INTO audit_events(actor, action, subject, detail) VALUES ($1,$2,$3,$4)", [
    actor,
    action,
    subject,
    JSON.stringify(detail),
  ]);
}
export type AgentIdentity = { device_id: string; context: "system"; hash: string };

export interface RouteContext {
  db: Database;
  config: Config;
  admin: ReturnType<typeof administratorAuth>;
  agent: (request: FastifyRequest) => Promise<AgentIdentity>;
}
