import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildApp } from "../../apps/control-plane/src/app.ts";
import { parseConfig } from "../../apps/control-plane/src/config.ts";
import { migrate, openDatabase } from "../../apps/control-plane/src/database.ts";
import { nativeFixture } from "../../apps/control-plane/tests/native-fixture.ts";

export async function consoleNativeFixture() {
  const token = () => randomBytes(32).toString("base64url");
  const env = {
    NODE_ENV: "development",
    DATABASE_URL: "local",
    DEV_OPERATOR_TOKEN: token(),
    DEV_APPROVER_TOKEN: token(),
    DEV_VIEWER_TOKEN: token(),
  };
  const native = await nativeFixture(env.DEV_OPERATOR_TOKEN);
  const db = await openDatabase("local");
  await migrate(db);
  const app = await buildApp(db, parseConfig({ ...env, NODE_ENV: "test", ...native.config }));
  await native.prepare(app);
  const headers = { authorization: `Bearer ${env.DEV_OPERATOR_TOKEN}` };
  for (const subject of ["local-viewer", "local-approver"]) {
    const version = (await app.inject({ url: `/v1/scopes/${native.scopeId}/modules`, headers })).json()
      .version;
    const granted = await app.inject({
      method: "PUT",
      url: `/v1/scopes/${native.scopeId}/grants`,
      headers,
      payload: {
        expectedVersion: version,
        issuer: "urn:one-control:local-development",
        subject,
        permission: "view",
        enabled: true,
      },
    });
    assert.equal(granted.statusCode, 200, granted.body);
  }
  const apiOrigin = await app.listen({ host: "127.0.0.1", port: 0 });
  const root = fileURLToPath(new URL("../../apps/console/", import.meta.url));
  const require = createRequire(join(root, "package.json"));
  const { createServer } = await import(pathToFileURL(require.resolve("vite")).href);
  const { default: react } = await import(pathToFileURL(require.resolve("@vitejs/plugin-react")).href);
  const cache = await mkdtemp(join(tmpdir(), "one-control-console-native-"));
  const server = await createServer({
    root,
    configFile: false,
    envDir: false,
    envPrefix: `FIXTURE_${randomUUID()}_`,
    cacheDir: cache,
    plugins: [react()],
    define: Object.fromEntries(
      ["VITE_OIDC_ISSUER", "VITE_OIDC_CLIENT_ID", "VITE_OIDC_AUDIENCE"].map((name) => [
        `import.meta.env.${name}`,
        '""',
      ]),
    ),
    server: {
      host: "127.0.0.1",
      port: 0,
      strictPort: true,
      open: false,
      proxy: { "/v1": apiOrigin, "/health": apiOrigin },
    },
  });
  await server.listen();
  const consoleOrigin = `http://127.0.0.1:${server.httpServer.address().port}`;
  return {
    env,
    apiOrigin,
    consoleOrigin,
    scopeId: native.scopeId,
    enroll: (hostname, invitation) => native.enroll(app, hostname, invitation),
    async agent(path, headers, payload) {
      const response = await native.inject(app, { method: "POST", url: path, headers, payload });
      assert.equal(response.statusCode, 200, response.body);
      return response.json();
    },
    async seedPresentationInventory(deviceId, inventory) {
      // Existing compatibility inventory screens are exercised with explicit
      // fixture data; this is not evidence from the native inventory provider.
      await db.query("UPDATE devices SET inventory=$2 WHERE id=$1", [deviceId, JSON.stringify(inventory)]);
    },
    async revoke(enrollmentId) {
      const response = await app.inject({
        method: "POST",
        url: `/v1/scopes/${native.scopeId}/native-enrollments/${enrollmentId}/revoke`,
        headers,
        payload: {},
      });
      assert.equal(response.statusCode, 200, response.body);
    },
    async close() {
      await server.close();
      await app.close();
      await db.close();
      await native.close();
      await rm(cache, { recursive: true, force: true });
    },
  };
}
