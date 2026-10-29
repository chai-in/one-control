import { z } from "zod";

const configSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  DEPLOYMENT_STAGE: z.enum(["poc", "production"]).default("poc"),
  POC_DEVICE_LIMIT: z.coerce.number().int().min(1).max(10).default(5),
  HOST: z.string().default("127.0.0.1"),
  PORT: z.coerce.number().int().min(1).max(65535).default(4317),
  DATABASE_URL: z.string().default("local"),
  LOCAL_DB_PATH: z.string().default("../../.local/control-plane"),
  DEV_OPERATOR_TOKEN: z.string().min(32).optional(),
  DEV_APPROVER_TOKEN: z.string().min(32).optional(),
  DEV_VIEWER_TOKEN: z.string().min(32).optional(),
  OIDC_ISSUER: z.url().optional(),
  OIDC_AUDIENCE: z.string().optional(),
  OPERATOR_SUBJECTS: z.string().default(""),
  APPROVER_SUBJECTS: z.string().default(""),
  VIEWER_SUBJECTS: z.string().default(""),
  FALCON_MANAGEMENT_SCOPE: z.uuid().optional(),
  NATIVE_AUTHORITY_CONFIG: z.string().optional(),
  CREDENTIAL_ROOT: z.string().optional(),
  ARTIFACT_READ_KEY_FILE: z.string().optional(),
  RECOVERY_ESCROW_KEYRING_FILE: z.string().optional(),
  OIDC_STEP_UP_ACRS: z.string().optional(),
  FALCON_WEBHOOK_SECRET: z.string().min(32).optional(),
  FALCON_SYNC_INTERVAL_SECONDS: z.coerce.number().int().min(0).max(86400).optional(),
  EMA_MANAGEMENT_SCOPE: z.uuid().optional(),
  RELEASE_PUBLIC_KEY_FILE: z.string().optional(),
  ARTIFACT_HOSTS: z.string().default(""),
  CONSOLE_DIST: z.string().default("../console/dist"),
  FALCON_CLOUD: z
    .enum([
      "https://api.crowdstrike.com",
      "https://api.us-2.crowdstrike.com",
      "https://api.eu-1.crowdstrike.com",
      "https://api.laggar.gcw.crowdstrike.com",
      "https://api.us-gov-2.crowdstrike.mil",
    ])
    .optional(),
  FALCON_CLIENT_ID: z.string().optional(),
  FALCON_CLIENT_SECRET: z.string().optional(),
  EMA_BASE_URL: z
    .url()
    .refine((value) => {
      const url = new URL(value);
      return (
        url.protocol === "https:" &&
        !url.username &&
        !url.password &&
        url.pathname === "/" &&
        !url.search &&
        !url.hash
      );
    }, "EMA requires an HTTPS origin without credentials, path, query or fragment")
    .optional(),
  EMA_USERNAME: z.string().min(1).optional(),
  EMA_PASSWORD: z.string().min(1).optional(),
});
export type Config = z.infer<typeof configSchema>;
export function parseConfig(env: NodeJS.ProcessEnv): Config {
  const config = configSchema.parse(env);
  if (config.NODE_ENV === "production") {
    if (
      config.DATABASE_URL === "local" ||
      !config.OIDC_ISSUER?.startsWith("https://") ||
      !config.OIDC_AUDIENCE
    )
      throw new Error("Production requires PostgreSQL and HTTPS OIDC issuer/audience");
    if (config.DEV_OPERATOR_TOKEN || config.DEV_APPROVER_TOKEN || config.DEV_VIEWER_TOKEN)
      throw new Error("Development authentication forbidden in production");
    let database: URL;
    try {
      database = new URL(config.DATABASE_URL);
    } catch {
      throw new Error("Production requires a valid PostgreSQL URL");
    }
    if (
      !["postgres:", "postgresql:"].includes(database.protocol) ||
      !database.hostname ||
      database.searchParams.getAll("sslmode").length !== 1 ||
      database.searchParams.get("sslmode") !== "verify-full" ||
      database.searchParams.has("ssl") ||
      env.NODE_TLS_REJECT_UNAUTHORIZED === "0"
    )
      throw new Error("Production PostgreSQL requires sslmode=verify-full and TLS certificate verification");
    if (
      !config.RELEASE_PUBLIC_KEY_FILE ||
      !config.ARTIFACT_HOSTS ||
      !config.OPERATOR_SUBJECTS ||
      !config.APPROVER_SUBJECTS
    )
      throw new Error("Production requires release trust, artifact allowlist and administrator subjects");
  } else if (!["127.0.0.1", "::1"].includes(config.HOST)) {
    throw new Error("Development/test server must bind to loopback");
  }
  if (
    Boolean(config.DEV_OPERATOR_TOKEN) !== Boolean(config.DEV_APPROVER_TOKEN) ||
    (config.DEV_OPERATOR_TOKEN === config.DEV_APPROVER_TOKEN && config.DEV_OPERATOR_TOKEN)
  )
    throw new Error("Local authentication requires two distinct tokens");
  const developmentTokens = [
    config.DEV_OPERATOR_TOKEN,
    config.DEV_APPROVER_TOKEN,
    config.DEV_VIEWER_TOKEN,
  ].filter(Boolean);
  if (new Set(developmentTokens).size !== developmentTokens.length)
    throw new Error("Local roles require distinct credentials");
  if (
    Boolean(config.FALCON_CLIENT_ID) !== Boolean(config.FALCON_CLIENT_SECRET) ||
    (config.FALCON_CLIENT_ID && !config.FALCON_CLOUD)
  )
    throw new Error("Incomplete Falcon configuration");
  const emaFields = [config.EMA_BASE_URL, config.EMA_USERNAME, config.EMA_PASSWORD];
  if (emaFields.some(Boolean) && !emaFields.every(Boolean)) throw new Error("Incomplete EMA configuration");
  return config;
}
