import { defineConfig } from "vitest/config";

if (process.platform !== "win32" || process.env.ONE_CONTROL_NATIVE_ACCEPTANCE !== "true")
  throw new Error("Native installation acceptance requires an explicitly selected Windows runner");
export default defineConfig({
  test: {
    include: ["tests/native-install.windows.ts"],
    testTimeout: 180_000,
    hookTimeout: 30_000,
    maxWorkers: 1,
  },
});
