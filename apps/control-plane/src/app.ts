import rateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyRequest } from "fastify";
import { z } from "zod";
import { registerAssetRoutes } from "../../../modules/asset-management/server/http.js";
import { registerReleasesRoutes } from "../../../modules/deployment/server/http.js";
import { registerDesktopRoutes } from "../../../modules/desktop-policies/server/http.js";
import { registerEmaRoutes } from "../../../modules/ema/server/http.js";
import { probeFalcon } from "../../../modules/falcon/server/capabilities.js";
import { registerFalconInventoryRoutes } from "../../../modules/falcon/server/http.js";
import { registerFalconEventRoutes } from "../../../modules/falcon-events/server/http.js";
import { registerFalconDataRoutes } from "../../../modules/falcon-sync/server/http.js";
import { registerNativeJobRoutes } from "../../../modules/native-dispatch/server/http.js";
import { registerNativePublicationRoutes } from "../../../modules/native-distribution/server/http.js";
import { registerNativeObservationRoutes } from "../../../modules/native-observations/server/http.js";
import { registerRecoveryEscrowRoutes } from "../../../modules/recovery-escrow/server/http.js";
import type { Config } from "./config.js";
import { type Database, TransactionCommitUnknownError } from "./database.js";
import { finishCleanup } from "./entrypoint-cleanup.js";
import { currentSchemaReady } from "./migrations.js";
import { createModuleControl } from "./module-control.js";
import type { AgentIdentity } from "./routes/context.js";
import { registerDispatchRoutes } from "./routes/dispatch.js";
import { registerEnrollmentRoutes } from "./routes/enrollment.js";
import { registerFleetRoutes } from "./routes/fleet.js";
import { registerJobsRoutes } from "./routes/jobs.js";
import { registerModuleRoutes } from "./routes/modules.js";
import { ApiError, administratorAuth, bearer, hash } from "./security.js";
export async function buildApp(db: Database, config: Config) {
  const identities = new WeakMap<FastifyRequest, AgentIdentity>();
  const app = Fastify({
    logger:
      config.NODE_ENV === "test"
        ? false
        : {
            redact: ["req.headers.authorization", "req.headers.cookie"],
            serializers: { req: (request) => ({ method: request.method }) },
          },
    bodyLimit: 262_144,
    requestTimeout: 30_000,
    connectionTimeout: 10_000,
  });
  try {
    await app.register(rateLimit, {
      max: 600,
      timeWindow: "1 minute",
      async keyGenerator(request) {
        // Hundreds of computers can share a NAT address. Only verified device identities get separate budgets.
        if (request.url.startsWith("/v1/agent/") && request.url !== "/v1/agent/enroll") {
          try {
            return `credential:${(await agent(request)).hash}`;
          } catch (error) {
            if (!(error instanceof ApiError && error.statusCode === 401)) throw error;
          }
        }
        return `ip:${request.ip}`;
      },
    });
    app.addHook("onSend", async (_request, reply) => {
      reply.header("Cache-Control", "no-store").header("X-Content-Type-Options", "nosniff");
    });
    app.setErrorHandler((error, request, reply) => {
      if (error instanceof TransactionCommitUnknownError) {
        request.log.error(
          { requestId: request.id, databaseOutcome: "unknown", retryAllowed: false },
          "Database commit outcome is unknown; inspect current durable state",
        );
        return reply.code(500).send({
          error: "database_commit_unknown",
          databaseOutcome: "unknown",
          retryAllowed: false,
          requestId: request.id,
        });
      }
      if (error instanceof ApiError)
        return reply.code(error.statusCode).send({ error: error.code, requestId: request.id });
      if (error instanceof z.ZodError || error instanceof SyntaxError)
        return reply.code(400).send({ error: "invalid_request", requestId: request.id });
      if (
        typeof error === "object" &&
        error !== null &&
        "statusCode" in error &&
        typeof error.statusCode === "number" &&
        error.statusCode < 500
      )
        return reply.code(error.statusCode).send({ error: "request_rejected", requestId: request.id });
      request.log.error({ requestId: request.id }, "Request failed; inspect restricted server diagnostics");
      return reply.code(500).send({ error: "internal_error", requestId: request.id });
    });
    const admin = administratorAuth(config);
    const modules = createModuleControl(db, config);
    async function agent(request: Parameters<typeof admin>[0]): Promise<AgentIdentity> {
      const cached = identities.get(request);
      if (cached) return cached;
      const tokenHash = hash(bearer(request));
      const identity = (
        await db.query<AgentIdentity & Record<string, unknown>>(
          `
      SELECT c.device_id, c.context, c.hash FROM credentials c JOIN devices d ON d.id=c.device_id
      WHERE c.hash=$1 AND c.enrollment_id IS NULL AND c.revoked_at IS NULL AND c.expires_at>now() AND d.revoked_at IS NULL`,
          [tokenHash],
        )
      )[0];
      if (identity?.context !== "system") throw new ApiError(401, "unauthorized");
      identities.set(request, identity);
      return identity;
    }
    app.get("/health/live", async () => ({ status: "ok", version: "0.1.0" }));
    app.get("/health/ready", async (_request, reply) => {
      try {
        if (!(await currentSchemaReady(db))) return reply.code(503).send({ status: "migration_required" });
        return { status: "ready" };
      } catch {
        return reply.code(503).send({ status: "database_unavailable" });
      }
    });
    app.get("/v1/integrations/falcon/capabilities", async (request) => {
      const actor = await admin(request, "viewer");
      const { scopeId } = z.strictObject({ scopeId: z.uuid() }).parse(request.query);
      return modules.integration(
        actor,
        scopeId,
        "GET /v1/integrations/falcon/capabilities",
        async (signal) => {
          try {
            return await probeFalcon(config, signal);
          } catch {
            throw new ApiError(503, "falcon_unavailable");
          }
        },
      );
    });
    registerFleetRoutes(app, { db, config, admin, agent });
    registerEmaRoutes(app, { db, config, admin, agent });
    registerEnrollmentRoutes(app, { db, config, admin, agent });
    registerReleasesRoutes(app, { db, config, admin, agent });
    registerJobsRoutes(app, { db, config, admin, agent });
    registerDispatchRoutes(app, { db, config, admin, agent });
    registerModuleRoutes(app, { db, config, admin, agent });
    registerFalconInventoryRoutes(app, { db, config, admin, agent });
    registerDesktopRoutes(app, { db, config, admin, agent });
    registerAssetRoutes(app, { db, config, admin, agent });
    registerNativePublicationRoutes(app, { db, config, admin, agent });
    registerNativeObservationRoutes(app, { db, config, admin, agent });
    registerNativeJobRoutes(app, { db, config, admin, agent });
    registerRecoveryEscrowRoutes(app, { db, config, admin, agent });
    registerFalconDataRoutes(app, { db, config, admin, agent });
    registerFalconEventRoutes(app, { db, config, admin, agent });
    return app;
  } catch (error) {
    await finishCleanup({ failed: true, error }, [() => app.close()]);
    throw error;
  }
}
