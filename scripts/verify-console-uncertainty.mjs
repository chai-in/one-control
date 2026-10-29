import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { chromium, expect } from "@playwright/test";

const root = fileURLToPath(new URL("../apps/console/", import.meta.url));
const require = createRequire(path.join(root, "package.json"));
const { createServer } = await import(pathToFileURL(require.resolve("vite")).href);
const { default: react } = await import(pathToFileURL(require.resolve("@vitejs/plugin-react")).href);
const evidence = fileURLToPath(
  new URL("../.local/orchestrate/full-build/evidence/database-http-client-implementation/", import.meta.url),
);
await mkdir(evidence, { recursive: true });
const cache = await mkdtemp(path.join(evidence, "console-cache-"));
let server;
let browser;
const mutations = [];
const unexpected = [];
const runtimeErrors = [];
const message =
  "The database outcome is unknown. Inspect the current state before submitting another change.";
try {
  const prefix = `ONE_CONTROL_FIXTURE_${randomUUID().replaceAll("-", "")}_`;
  server = await createServer({
    root,
    configFile: false,
    envDir: false,
    envPrefix: prefix,
    cacheDir: cache,
    plugins: [react()],
    define: Object.fromEntries(
      ["VITE_OIDC_ISSUER", "VITE_OIDC_CLIENT_ID", "VITE_OIDC_AUDIENCE"].map((name) => [
        `import.meta.env.${name}`,
        '""',
      ]),
    ),
    server: { host: "127.0.0.1", port: 0, strictPort: true, open: false },
  });
  assert.equal(server.config.configFile, undefined);
  assert.equal(server.config.envDir, false);
  assert.equal(server.config.envPrefix, prefix);
  assert.equal(path.resolve(server.config.cacheDir), path.resolve(cache));
  assert.equal(
    Object.keys(server.config.env).some((name) => name.startsWith("VITE_")),
    false,
  );
  await server.listen();
  const address = server.httpServer.address();
  assert.equal(typeof address, "object");
  assert.equal(address.address, "127.0.0.1");
  const origin = `http://127.0.0.1:${address.port}`;
  browser = await chromium.launch();
  const page = await browser.newPage();
  page.on("pageerror", (error) => runtimeErrors.push(error.message));
  const device = {
    id: randomUUID(),
    hostname: "UNCERTAINTY-FIXTURE",
    ring: "canary",
    context: "system",
    platform: "windows",
    enrolled_at: new Date().toISOString(),
    last_seen_at: new Date().toISOString(),
    revoked_at: null,
    inventory: {},
  };
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) {
      unexpected.push(url.origin);
      await route.abort();
      return;
    }
    if (!url.pathname.startsWith("/v1/")) {
      await route.continue();
      return;
    }
    if (url.pathname === "/v1/batches" && route.request().method() === "POST") {
      mutations.push({ key: route.request().headers()["idempotency-key"], body: route.request().postData() });
      await route.fulfill({
        status: 500,
        json: {
          error: "database_commit_unknown",
          databaseOutcome: "unknown",
          retryAllowed: false,
          requestId: "fixture",
        },
      });
      return;
    }
    const bodies = {
      "/v1/me": { subject: "fixture-operator", roles: ["operator"] },
      "/v1/devices": { devices: [device] },
      "/v1/jobs": { jobs: [] },
      "/v1/audit": { events: [] },
      "/v1/releases": { releases: [] },
      "/v1/workspace": { deploymentStage: "poc", deviceLimit: 5 },
    };
    if (!(url.pathname in bodies) || route.request().method() !== "GET") {
      unexpected.push(url.pathname);
      await route.abort();
      return;
    }
    await route.fulfill({ json: bodies[url.pathname] });
  });
  await page.goto(origin);
  const token = randomUUID();
  const login = async () => {
    await page.getByLabel("Local development access token").fill(token);
    await page.getByRole("button", { name: "Open operations console" }).click();
    await expect(page.getByRole("heading", { name: "Fleet overview", exact: true })).toBeVisible();
  };
  await login();
  const open = async () => {
    await page.getByRole("button", { name: "New operation", exact: true }).click();
    await page.getByLabel(device.hostname, { exact: true }).check();
  };
  const submit = async (count) => {
    await page.getByRole("button", { name: "Create operation", exact: true }).click();
    await expect(page.getByRole("alert")).toHaveText(message);
    await expect.poll(() => mutations.length).toBe(count);
  };
  await open();
  const start = await page.getByLabel("Start (your local time)").inputValue();
  await submit(1);
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByLabel(device.hostname, { exact: true })).toBeChecked();
  await expect(page.getByLabel("Start (your local time)")).toHaveValue(start);
  await page.waitForTimeout(250);
  assert.equal(mutations.length, 1);
  await submit(2);
  assert.deepEqual(mutations[0], mutations[1]);
  await page.getByLabel("Operation", { exact: true }).selectOption("windows.scan");
  await submit(3);
  assert.notEqual(mutations[1].key, mutations[2].key);
  assert.notEqual(mutations[1].body, mutations[2].body);
  await page.getByRole("button", { name: "Close dialog", exact: true }).click();
  await open();
  await submit(4);
  assert.notEqual(mutations[0].key, mutations[3].key);
  await page.getByRole("button", { name: "Close dialog", exact: true }).click();
  await page.getByRole("button", { name: /Sign out/ }).click();
  await login();
  await open();
  await submit(5);
  assert.notEqual(mutations[3].key, mutations[4].key);
  await page.reload();
  await expect(page.getByLabel("Local development access token")).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  assert.equal(mutations.length, 5);
  assert.deepEqual(unexpected, []);
  assert.deepEqual(runtimeErrors, []);
  await writeFile(
    path.join(evidence, "console-verdict.json"),
    `${JSON.stringify({ isolation: true, explicitSubmits: mutations.length, unchangedKeyAndBody: true, changedKey: true, modalCloseNondurable: true, logoutNondurable: true, reloadNondurable: true, unexpected, runtimeErrors }, null, 2)}\n`,
  );
  console.log(
    "Console uncertainty passed with five explicit submits, stable unchanged identity and isolated real components.",
  );
} finally {
  try {
    await browser?.close();
  } finally {
    try {
      await server?.close();
    } finally {
      assert.equal(path.dirname(path.resolve(cache)), path.resolve(evidence));
      await rm(cache, { recursive: true, force: true });
    }
  }
}
