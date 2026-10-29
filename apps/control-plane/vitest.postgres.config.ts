import { defineConfig } from "vitest/config";

if (
  !["owned-local", "ci-service"].includes(process.env.ONE_CONTROL_POSTGRES_PROFILE ?? "") ||
  !process.env.ONE_CONTROL_POSTGRES_CUSTODY
) {
  throw new Error("Required PostgreSQL tests must run through the owned runner");
}

export default defineConfig({
  test: {
    include: [
      "tests/control-plane.test.ts",
      "tests/heartbeat-revocation.test.ts",
      "tests/rotation-revocation.test.ts",
      "tests/dispatch-revocation.test.ts",
      "tests/releases.test.ts",
      "tests/native-presence.test.ts",
      "tests/native-artifacts.test.ts",
      "tests/product-boundary.test.ts",
      "tests/poc-boundary.test.ts",
      "tests/database-fixture.test.ts",
      "tests/postgres/*.postgres.ts",
    ],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    maxWorkers: 1,
    pool: "threads",
  },
});
