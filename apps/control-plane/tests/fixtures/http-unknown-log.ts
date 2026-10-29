import { buildApp } from "../../src/app.js";
import type { Config } from "../../src/config.js";
import { type Database, TransactionCommitUnknownError } from "../../src/database.js";

const config: Config = {
  NODE_ENV: "development",
  DEPLOYMENT_STAGE: "poc",
  POC_DEVICE_LIMIT: 5,
  HOST: "127.0.0.1",
  PORT: 4317,
  DATABASE_URL: "local",
  LOCAL_DB_PATH: "unused",
  OPERATOR_SUBJECTS: "",
  APPROVER_SUBJECTS: "",
  VIEWER_SUBJECTS: "",
  ARTIFACT_HOSTS: "",
  CONSOLE_DIST: "unused",
};
let mode = "unknown";
let callbacks = 0;
const db: Database = {
  async query<T extends Record<string, unknown>>(sql: string): Promise<T[]> {
    if (sql.startsWith("UPDATE enrollment_tokens")) return [{ context: "system" }] as unknown as T[];
    if (sql.startsWith("SELECT count(*)")) return [{ active: 0 }] as unknown as T[];
    return [];
  },
  async transaction(work) {
    callbacks++;
    await work(this);
    if (mode === "lookalike") throw { outcome: "unknown", retryAllowed: false, cause: "CAUSE_CANARY" };
    if (mode === "generic") throw new Error("SQL_CANARY PARAM_CANARY CAUSE_CANARY");
    const error = new TransactionCommitUnknownError();
    Object.assign(error, { sql: "SQL_CANARY", params: ["PARAM_CANARY"], cause: "CAUSE_CANARY" });
    throw error;
  },
  async close() {},
};
const app = await buildApp(db, config);
try {
  for (const scenario of ["unknown", "lookalike", "generic"]) {
    mode = scenario;
    const before = callbacks;
    const response = await app.inject({
      method: "POST",
      url: "/v1/agent/enroll?secret=QUERY_CANARY",
      headers: {
        authorization: "Bearer AUTH_CANARY",
        cookie: "COOKIE_CANARY",
        "content-type": "application/json",
      },
      payload: { token: "BODY_CANARY".repeat(4), hostname: "fixture-host" },
    });
    process.stdout.write(
      `${JSON.stringify({ scenario, fixtureResponse: response.json(), status: response.statusCode, callbacks: callbacks - before, retryAfter: response.headers["retry-after"] ?? null })}\n`,
    );
  }
} finally {
  await app.close();
}
