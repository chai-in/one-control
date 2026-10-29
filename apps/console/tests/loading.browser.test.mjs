import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { chromium, expect } from "@playwright/test";

const root = fileURLToPath(new URL("../", import.meta.url));
const evidence = fileURLToPath(new URL("../../../.local/alpha-work/console/", import.meta.url));
const require = createRequire(path.join(root, "package.json"));
const { createServer } = await import(pathToFileURL(require.resolve("vite")).href);
const { default: react } = await import(pathToFileURL(require.resolve("@vitejs/plugin-react")).href);
await mkdir(evidence, { recursive: true });
const cacheDir = await mkdtemp(path.join(evidence, "browser-cache-"));
const prefix = `CONSOLE_FIXTURE_${randomUUID().replaceAll("-", "")}_`;
const server = await createServer({
  root,
  configFile: false,
  envDir: false,
  envPrefix: prefix,
  cacheDir,
  plugins: [react()],
  define: Object.fromEntries(
    ["VITE_OIDC_ISSUER", "VITE_OIDC_CLIENT_ID", "VITE_OIDC_AUDIENCE"].map((name) => [
      `import.meta.env.${name}`,
      '""',
    ]),
  ),
  server: { host: "127.0.0.1", port: 0, strictPort: true, open: false },
});
assert.equal(server.config.envDir, false);
assert.equal(server.config.envPrefix, prefix);
assert.equal(
  Object.keys(server.config.env).some((name) => name.startsWith("VITE_")),
  false,
);
await server.listen();
const address = server.httpServer.address();
assert.equal(address.address, "127.0.0.1");
const origin = `http://127.0.0.1:${address.port}`;
const browser = await chromium.launch();
const results = [];
const device = {
  id: "11111111-1111-4111-8111-111111111111",
  hostname: "FIXTURE-PC",
  ring: "canary",
  created_at: new Date().toISOString(),
  last_seen_at: new Date().toISOString(),
  revoked_at: null,
  inventory: {},
};
const job = {
  id: "22222222-2222-4222-8222-222222222222",
  batch_id: "33333333-3333-4333-8333-333333333333",
  device_id: device.id,
  kind: "inventory.scan",
  command: { kind: "inventory.scan" },
  context: "system",
  state: "queued",
  starts_at: new Date().toISOString(),
  ends_at: new Date(Date.now() + 3_600_000).toISOString(),
  created_at: new Date().toISOString(),
  created_by: "fixture-owner",
  attempt: 0,
  result: null,
};
const defaults = {
  "/v1/me": { subject: "fixture-owner", roles: ["operator", "approver"] },
  "/v1/devices": { devices: [device] },
  "/v1/jobs": { jobs: [] },
  "/v1/audit": { events: [] },
  "/v1/releases": { releases: [] },
  "/v1/workspace": { deploymentStage: "production", deviceLimit: null },
  "/v1/integrations/falcon/capabilities": { configured: true, capabilities: [] },
  "/v1/integrations/ema/endpoints": { configured: true, endpoints: [] },
};
const names = {
  "/v1/jobs": "Operations",
  "/v1/audit": "Audit",
  "/v1/releases": "Releases",
  "/v1/workspace": "Workspace settings",
};
const section = (page, name) => page.locator(`[data-section="${name}"]`);
const fleet = (page) => page.getByRole("heading", { name: "Fleet overview", exact: true });
const refresh = (page) => page.getByRole("button", { name: "Refresh data", exact: true }).click();
function gate() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
async function settle(page, endpoint, held, response) {
  const received = page.waitForResponse((result) => new URL(result.url()).pathname === endpoint);
  held.resolve(response);
  await received;
  await page.waitForLoadState("networkidle");
}
async function scenario(name, run) {
  if (process.argv[2] && !name.includes(process.argv[2])) return;
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.setDefaultTimeout(5000);
  const overrides = new Map();
  const counts = new Map();
  const errors = [];
  const requests = [];
  const pending = [];
  await page.clock.setFixedTime(new Date("2026-10-20T10:00:00Z"));
  page.on("pageerror", (error) => errors.push(error.message));
  await page.addInitScript(() => {
    const original = window.fetch;
    window.fetch = (input, options) => original(input, { ...options, signal: undefined });
  });
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) {
      errors.push(`Unexpected external request ${url.origin}`);
      await route.abort();
      return;
    }
    if (!url.pathname.startsWith("/v1/")) return route.continue();
    const count = (counts.get(url.pathname) ?? 0) + 1;
    counts.set(url.pathname, count);
    requests.push({ path: url.pathname, token: route.request().headers().authorization, count });
    let response = overrides.get(url.pathname);
    if (typeof response === "function") response = response(count, route.request());
    response = await response;
    try {
      await route.fulfill(response ?? { json: defaults[url.pathname] ?? { error: "unexpected_route" } });
    } catch (error) {
      if (!page.isClosed()) throw error;
    }
  });
  const hold = (endpoint) => {
    const held = gate();
    pending.push(held);
    overrides.set(endpoint, held.promise);
    return held;
  };
  const login = async (token = "fixture-A") => {
    await page.getByLabel("Local development access token").fill(token);
    await page.getByRole("button", { name: "Open operations console", exact: true }).click();
  };
  try {
    await page.goto(origin);
    await run({ page, overrides, counts, requests, hold, login });
    assert.deepEqual(errors, []);
    results.push({ name, passed: true });
    console.log(`PASS ${name}`);
  } catch (error) {
    await page.screenshot({ path: path.join(evidence, "loading-failure.png"), fullPage: true });
    await writeFile(path.join(evidence, "loading-failure.txt"), await page.locator("body").innerText());
    results.push({ name, passed: false, error: String(error) });
    throw error;
  } finally {
    await page.close();
    for (const held of pending) held.resolve({ status: 503, json: { error: "fixture_closed" } });
  }
}
try {
  for (const [endpoint, name] of Object.entries(names)) {
    await scenario(`${name} failure leaves authorized fleet`, async ({ page, overrides, login }) => {
      overrides.set(endpoint, { status: 503, json: { error: "unavailable" } });
      await login();
      await expect(fleet(page)).toBeVisible();
      await expect(section(page, name)).toHaveAttribute("data-state", "failed");
      if (endpoint !== "/v1/audit")
        await expect(page.getByRole("button", { name: "New operation", exact: true })).toBeDisabled();
      await page.getByRole("button", { name: "Device fleet", exact: true }).click();
      await expect(page.getByText(device.hostname, { exact: true })).toBeVisible();
      await page.getByText(device.hostname, { exact: true }).click();
      await page.getByRole("button", { name: "Close details", exact: true }).click();
      await expect(page.getByRole("dialog")).toHaveCount(0);
    });
    await scenario(`${name} pending publishes other sections`, async ({ page, hold, login }) => {
      const held = hold(endpoint);
      await login();
      await expect(fleet(page)).toBeVisible();
      await expect(section(page, name)).toHaveAttribute("data-state", "loading");
      const other = name === "Audit" ? "Releases" : "Audit";
      await expect(section(page, other)).toHaveAttribute("data-state", "loaded");
      held.resolve({ json: defaults[endpoint] });
      await expect(section(page, name)).toHaveAttribute("data-state", "loaded");
    });
  }
  for (const endpoint of ["/v1/me", "/v1/devices"]) {
    for (const status of [401, 403]) {
      for (const initial of [true, false]) {
        await scenario(
          `${endpoint} ${status} ${initial ? "initial" : "refresh"} clears protected views`,
          async ({ page, overrides, login }) => {
            if (!initial) {
              await login();
              await expect(fleet(page)).toBeVisible();
              await expect(section(page, "Workspace settings")).toHaveAttribute("data-state", "loaded");
              await page.getByRole("button", { name: "Enroll computer", exact: true }).click();
              await expect(page.getByRole("dialog")).toBeVisible();
            }
            overrides.set(endpoint, { status, json: { error: "forbidden" } });
            if (initial) await login();
            else
              await page
                .getByRole("button", { name: "Refresh data", exact: true })
                .evaluate((button) => button.click());
            await expect(page.getByLabel("Local development access token")).toBeVisible();
            await expect(page.getByRole("dialog")).toHaveCount(0);
            await expect(fleet(page)).toHaveCount(0);
            await expect(page.getByText(device.hostname, { exact: true })).toHaveCount(0);
            await expect(page.getByRole("alert")).toContainText(status === 401 ? "Sign in again" : "denied");
          },
        );
      }
    }
  }
  await scenario(
    "required denial is immediate with a pending sibling",
    async ({ page, overrides, hold, login }) => {
      hold("/v1/devices");
      overrides.set("/v1/me", { status: 403, json: { error: "forbidden" } });
      await login();
      await expect(page.getByRole("alert")).toContainText("denied", { timeout: 1500 });
    },
  );
  await scenario("optional 401 ends the session", async ({ page, overrides, login }) => {
    overrides.set("/v1/audit", { status: 401, body: "not JSON" });
    await login();
    await expect(page.getByRole("alert")).toContainText("Sign in again");
    await expect(fleet(page)).toHaveCount(0);
  });
  for (const [endpoint, name] of Object.entries(names)) {
    await scenario(`${name} denial drops its previous snapshot`, async ({ page, overrides, login }) => {
      await login();
      await expect(section(page, name)).toHaveAttribute("data-state", "loaded");
      overrides.set(endpoint, { status: 403, json: { error: "forbidden" } });
      await refresh(page);
      await expect(section(page, name)).toHaveAttribute("data-state", "failed");
      await expect(section(page, name)).toContainText("Access denied");
      await expect(section(page, name)).not.toContainText("stale data");
      await expect(fleet(page)).toBeVisible();
    });
  }
  for (const status of [200, 401, 403, 500]) {
    await scenario(
      `token replacement suppresses late ${status}`,
      async ({ page, hold, overrides, login }) => {
        const held = hold("/v1/jobs");
        await login();
        await expect(section(page, "Operations")).toHaveAttribute("data-state", "loading");
        await page.getByRole("button", { name: /Sign out/ }).click();
        overrides.delete("/v1/jobs");
        overrides.set("/v1/me", { json: { subject: "fixture-B", roles: ["viewer"] } });
        await login("fixture-B");
        await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
        await settle(page, "/v1/jobs", held, {
          status,
          json: status === 200 ? { jobs: [job] } : { error: "forbidden" },
        });
        await expect(page.getByRole("button", { name: "Sign out · fixture-B" })).toBeVisible();
        await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
        await expect(page.getByRole("heading", { name: "No operations yet" })).toBeVisible();
      },
    );
  }
  for (const status of [200, 500]) {
    await scenario(
      `new forced core refresh defeats older ${status}`,
      async ({ page, overrides, hold, counts, login }) => {
        await login();
        await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
        const held = hold("/v1/devices");
        await refresh(page);
        await expect.poll(() => counts.get("/v1/devices")).toBe(2);
        overrides.set("/v1/devices", { json: { devices: [{ ...device, hostname: "NEWER-PC" }] } });
        await refresh(page);
        await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
        await settle(page, "/v1/devices", held, {
          status,
          json:
            status === 200 ? { devices: [{ ...device, hostname: "OLDER-PC" }] } : { error: "unavailable" },
        });
        await page.getByRole("button", { name: "Device fleet", exact: true }).click();
        await expect(page.getByText("NEWER-PC", { exact: true })).toBeVisible();
        await expect(page.getByText("OLDER-PC", { exact: true })).toHaveCount(0);
        await expect(page.getByRole("alert")).toHaveCount(0);
      },
    );
  }
  await scenario(
    "partial refresh keeps stale snapshot and retry replaces it",
    async ({ page, overrides, login }) => {
      overrides.set("/v1/jobs", { json: { jobs: [job] } });
      await login();
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      const original = await section(page, "Operations").textContent();
      await page.clock.setFixedTime(new Date("2026-10-20T10:02:00Z"));
      overrides.set("/v1/jobs", { status: 503, json: { error: "unavailable" } });
      await refresh(page);
      await expect(section(page, "Operations")).toContainText("Showing stale data from");
      await expect(section(page, "Audit")).toHaveAttribute("data-state", "loaded");
      assert.ok((await section(page, "Operations").textContent()).includes(original.split("Updated ")[1]));
      await expect(page.getByRole("button", { name: "New operation", exact: true })).toBeDisabled();
      await expect(page.getByText("FIXTURE-PC", { exact: true })).toBeVisible();
      overrides.delete("/v1/jobs");
      await refresh(page);
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      await expect(section(page, "Operations")).not.toContainText("stale");
      assert.notEqual(await section(page, "Operations").textContent(), original);
      await expect(page.getByRole("heading", { name: "No operations yet" })).toBeVisible();
      await expect(page.getByRole("button", { name: "New operation", exact: true })).toBeEnabled();
    },
  );
  for (const status of [403, 404, 405, 501, 500]) {
    await scenario(
      `malformed HTTP ${status} preserves classification`,
      async ({ page, overrides, login }) => {
        overrides.set("/v1/releases", { status, body: "<html>upstream</html>", contentType: "text/html" });
        await login();
        await expect(fleet(page)).toBeVisible();
        await expect(section(page, "Releases")).toHaveAttribute(
          "data-state",
          [404, 405, 501].includes(status) ? "unsupported" : "failed",
        );
        await expect(section(page, "Releases")).toContainText(`HTTP ${status}`);
        await page.getByRole("button", { name: "Release catalogue", exact: true }).click();
        await expect(page.getByRole("heading", { name: "Trust comes before installation" })).toHaveCount(0);
        await expect(
          page.getByRole("button", { name: "Register signed release", exact: true }),
        ).toBeDisabled();
      },
    );
  }
  await scenario("loaded empty collections differ from unavailable collections", async ({ page, login }) => {
    await login();
    await expect(section(page, "Releases")).toHaveAttribute("data-state", "loaded");
    await page.getByRole("button", { name: "Release catalogue", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Trust comes before installation" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Register signed release", exact: true })).toBeEnabled();
    await page.getByRole("button", { name: "Audit trail", exact: true }).click();
    await expect(page.getByText("No audit events returned.", { exact: true })).toBeVisible();
  });
  for (const endpoint of ["/v1/jobs", "/v1/releases", "/v1/audit", "/v1/workspace"]) {
    await scenario(`${endpoint} malformed success stays isolated`, async ({ page, overrides, login }) => {
      overrides.set(endpoint, { json: { error: "bad_envelope" } });
      await login();
      await expect(fleet(page)).toBeVisible();
      await expect(section(page, names[endpoint])).toHaveAttribute("data-state", "failed");
    });
  }
  await scenario("invalid identity never grants fleet access", async ({ page, overrides, login }) => {
    overrides.set("/v1/me", { json: { subject: "bad" } });
    await login();
    await expect(page.getByRole("alert")).toContainText("invalid identity");
    await expect(fleet(page)).toHaveCount(0);
  });
  for (const [endpoint, field] of [
    ["/v1/jobs", "jobs"],
    ["/v1/audit", "events"],
    ["/v1/releases", "releases"],
  ]) {
    await scenario(`${endpoint} null row cannot erase fleet`, async ({ page, overrides, login }) => {
      overrides.set(endpoint, { json: { [field]: [null] } });
      await login();
      await expect(fleet(page)).toBeVisible();
      await expect(section(page, names[endpoint])).toHaveAttribute("data-state", "failed");
      await expect(section(page, names[endpoint])).toContainText("invalid collection data");
    });
  }
  await scenario("malformed required fleet rows never grant access", async ({ page, overrides, login }) => {
    overrides.set("/v1/devices", { json: { devices: [null] } });
    await login();
    await expect(page.getByRole("alert")).toContainText("invalid collection data");
    await expect(fleet(page)).toHaveCount(0);
  });
  await scenario(
    "required malformed 403 ends the session immediately",
    async ({ page, overrides, hold, login }) => {
      hold("/v1/devices");
      overrides.set("/v1/me", { status: 403, body: "<html>forbidden</html>" });
      await login();
      await expect(page.getByRole("alert")).toContainText("denied", { timeout: 1500 });
      await expect(page.getByRole("button", { name: "Retry current session", exact: true })).toHaveCount(0);
    },
  );
  await scenario(
    "core failure does not invent optional HTTP outcomes",
    async ({ page, overrides, login }) => {
      await login();
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      overrides.set("/v1/me", { status: 404, json: { error: "not_found" } });
      await refresh(page);
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "failed");
      await expect(section(page, "Operations")).toContainText(
        "Not refreshed because identity or fleet could not refresh",
      );
      await expect(section(page, "Operations")).not.toContainText("HTTP");
      await expect(page.getByRole("button", { name: "New operation", exact: true })).toBeDisabled();
    },
  );
  for (const status of [200, 403, 500]) {
    await scenario(
      `new optional refresh defeats older ${status}`,
      async ({ page, hold, overrides, counts, login }) => {
        await login();
        await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
        const held = hold("/v1/jobs");
        await refresh(page);
        await expect.poll(() => counts.get("/v1/jobs")).toBe(2);
        overrides.set("/v1/jobs", { json: { jobs: [job] } });
        await refresh(page);
        await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
        await settle(page, "/v1/jobs", held, {
          status,
          json: status === 200 ? { jobs: [] } : { error: "forbidden" },
        });
        await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
        await expect(page.getByText(device.hostname, { exact: true })).toBeVisible();
      },
    );
  }
  await scenario(
    "mutation receipt survives a healthy automatic poll",
    async ({ page, hold, counts, login }) => {
      await page.clock.install({ time: new Date("2026-10-20T10:00:00Z") });
      await login();
      await expect(section(page, "Workspace settings")).toHaveAttribute("data-state", "loaded");
      const held = hold("/v1/enrollment-tokens");
      await page.getByRole("button", { name: "Enroll computer", exact: true }).click();
      await page.getByRole("button", { name: "Create enrollment token", exact: true }).click();
      await page.clock.fastForward(15_001);
      await expect.poll(() => counts.get("/v1/devices")).toBe(2);
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      await expect(page.getByRole("button", { name: "New operation", exact: true })).toBeDisabled();
      held.resolve({ json: { token: "OLD-REQUEST-TOKEN", expiresAt: "2026-10-20T10:15:00Z" } });
      await expect(page.getByLabel("One-time token")).toHaveValue("OLD-REQUEST-TOKEN");
      await page.getByRole("button", { name: "Close dialog", exact: true }).click();
      await expect(page.getByRole("button", { name: "New operation", exact: true })).toBeEnabled();
    },
  );
  await scenario(
    "automatic poll does not supersede a slow optional read",
    async ({ page, hold, counts, login }) => {
      await page.clock.install({ time: new Date("2026-10-20T10:00:00Z") });
      const held = hold("/v1/jobs");
      await login();
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loading");
      await page.clock.fastForward(15_001);
      await expect.poll(() => counts.get("/v1/devices")).toBe(1);
      assert.equal(counts.get("/v1/jobs"), 1);
      held.resolve({ json: { jobs: [job] } });
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      await expect(page.getByText(device.hostname, { exact: true })).toBeVisible();
      await page.clock.fastForward(15_001);
      await expect.poll(() => counts.get("/v1/devices")).toBe(2);
    },
  );
  await scenario(
    "unrelated release denial preserves an enrollment receipt",
    async ({ page, overrides, hold, login }) => {
      await page.clock.install({ time: new Date("2026-10-20T10:00:00Z") });
      await login();
      await expect(section(page, "Workspace settings")).toHaveAttribute("data-state", "loaded");
      const held = hold("/v1/enrollment-tokens");
      await page.getByRole("button", { name: "Enroll computer", exact: true }).click();
      await page.getByRole("button", { name: "Create enrollment token", exact: true }).click();
      overrides.set("/v1/releases", { status: 404, json: { error: "not_found" } });
      await page.clock.fastForward(15_001);
      await expect(section(page, "Releases")).toHaveAttribute("data-state", "unsupported");
      await expect(section(page, "Workspace settings")).toHaveAttribute("data-state", "loaded");
      held.resolve({ json: { token: "PRESERVED-ENROLLMENT", expiresAt: "2026-10-20T10:15:00Z" } });
      await expect(page.getByLabel("One-time token")).toHaveValue("PRESERVED-ENROLLMENT");
      await page.getByRole("button", { name: "Close dialog", exact: true }).click();
    },
  );
  await scenario(
    "automatic poll preserves a mutation uncertainty result",
    async ({ page, hold, counts, login }) => {
      await page.clock.install({ time: new Date("2026-10-20T10:00:00Z") });
      await login();
      await expect(section(page, "Workspace settings")).toHaveAttribute("data-state", "loaded");
      const held = hold("/v1/batches");
      await page.getByRole("button", { name: "New operation", exact: true }).click();
      await page.getByLabel(device.hostname, { exact: true }).check();
      await page.getByRole("button", { name: "Create operation", exact: true }).click();
      await expect.poll(() => counts.get("/v1/batches")).toBe(1);
      await page.clock.fastForward(15_001);
      await expect.poll(() => counts.get("/v1/devices")).toBe(2);
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      await expect(page.getByRole("button", { name: "Create operation", exact: true })).toBeDisabled();
      held.resolve({ status: 500, json: { error: "database_commit_unknown" } });
      await expect(page.getByRole("alert")).toContainText("The database outcome is unknown");
      await expect(page.getByLabel(device.hostname, { exact: true })).toBeChecked();
      assert.equal(counts.get("/v1/batches"), 1);
    },
  );
  await scenario(
    "denied jobs cannot resurrect a late batch review",
    async ({ page, overrides, hold, login }) => {
      overrides.set("/v1/jobs", {
        json: { jobs: [{ ...job, state: "awaiting_approval", created_by: "another-operator" }] },
      });
      await login();
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      const held = hold(`/v1/batches/${job.batch_id}`);
      await page.getByRole("button", { name: "Review batch", exact: true }).click();
      overrides.set("/v1/jobs", { status: 403, json: { error: "forbidden" } });
      await refresh(page);
      await expect(section(page, "Operations")).toContainText("Access denied");
      await settle(page, `/v1/batches/${job.batch_id}`, held, {
        json: {
          id: job.batch_id,
          createdBy: "another-operator",
          createdAt: job.created_at,
          command: job.command,
          ring: "canary",
          targets: [],
          release: null,
          reviewDigest: "old-review",
        },
      });
      await expect(page.getByRole("dialog")).toHaveCount(0);
      overrides.delete("/v1/jobs");
      await refresh(page);
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      await expect(page.getByRole("dialog")).toHaveCount(0);
    },
  );
  await scenario(
    "approval review survives refresh with approval disabled until inputs recover",
    async ({ page, overrides, hold, login }) => {
      await page.clock.install({ time: new Date("2026-10-20T10:00:00Z") });
      overrides.set("/v1/jobs", {
        json: { jobs: [{ ...job, state: "awaiting_approval", created_by: "another-operator" }] },
      });
      overrides.set(`/v1/batches/${job.batch_id}`, {
        json: {
          id: job.batch_id,
          createdBy: "another-operator",
          createdAt: job.created_at,
          command: job.command,
          ring: "canary",
          targets: [],
          release: null,
          reviewDigest: "current-review",
        },
      });
      await login();
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      await page.getByRole("button", { name: "Review batch", exact: true }).click();
      await expect(page.getByRole("dialog")).toBeVisible();
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      const confirmation = page.getByRole("checkbox", {
        name: "I reviewed the exact operation and every target above.",
      });
      await confirmation.check();
      await expect(page.getByRole("button", { name: "Approve reviewed batch", exact: true })).toBeEnabled();
      const held = hold("/v1/jobs");
      await page.clock.fastForward(15_001);
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loading");
      await expect(page.getByRole("dialog")).toBeVisible();
      await expect(confirmation).toBeChecked();
      await expect(page.getByRole("button", { name: "Approve reviewed batch", exact: true })).toBeDisabled();
      held.resolve({
        json: { jobs: [{ ...job, state: "awaiting_approval", created_by: "another-operator" }] },
      });
      await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
      await expect(confirmation).toBeChecked();
      await expect(page.getByRole("button", { name: "Approve reviewed batch", exact: true })).toBeEnabled();
    },
  );
  for (const integration of [
    {
      nav: "CrowdStrike",
      name: "Falcon",
      button: "Check read capabilities",
      endpoint: "/v1/integrations/falcon/capabilities",
    },
    {
      nav: "Intel EMA",
      name: "Intel EMA",
      button: "Read EMA inventory",
      endpoint: "/v1/integrations/ema/endpoints",
    },
  ]) {
    await scenario(
      `${integration.name} retains loaded data through fleet refresh and clears denied data`,
      async ({ page, overrides, login }) => {
        await login();
        await expect(fleet(page)).toBeVisible();
        await page.getByRole("button", { name: integration.nav, exact: true }).click();
        await page.getByRole("button", { name: integration.button, exact: true }).click();
        await expect(section(page, integration.name)).toHaveAttribute("data-state", "loaded");
        await refresh(page);
        await expect(section(page, "Operations")).toHaveAttribute("data-state", "loaded");
        await expect(section(page, integration.name)).toHaveAttribute("data-state", "loaded");
        overrides.set(integration.endpoint, { status: 403, json: { error: "forbidden" } });
        await page.getByRole("button", { name: integration.button, exact: true }).click();
        await expect(section(page, integration.name)).toHaveAttribute("data-state", "failed");
        await expect(section(page, integration.name)).toContainText("Access denied");
        await expect(section(page, integration.name)).not.toContainText("stale");
      },
    );
    await scenario(`${integration.name} malformed rows stay isolated`, async ({ page, overrides, login }) => {
      overrides.set(integration.endpoint, {
        json: { configured: true, [integration.name === "Falcon" ? "capabilities" : "endpoints"]: [null] },
      });
      await login();
      await expect(fleet(page)).toBeVisible();
      await page.getByRole("button", { name: integration.nav, exact: true }).click();
      await page.getByRole("button", { name: integration.button, exact: true }).click();
      await expect(section(page, integration.name)).toHaveAttribute("data-state", "failed");
    });
    await scenario(
      `${integration.name} failures stay isolated and unmounted responses stay gone`,
      async ({ page, overrides, hold, login }) => {
        await login();
        await expect(fleet(page)).toBeVisible();
        await page.getByRole("button", { name: integration.nav, exact: true }).click();
        overrides.set(integration.endpoint, { status: 404, body: "not JSON" });
        await page.getByRole("button", { name: integration.button, exact: true }).click();
        await expect(section(page, integration.name)).toHaveAttribute("data-state", "unsupported");
        const held = hold(integration.endpoint);
        await page.getByRole("button", { name: integration.button, exact: true }).click();
        await expect(section(page, integration.name)).toHaveAttribute("data-state", "loading");
        await page.getByRole("button", { name: "Overview", exact: true }).click();
        await settle(page, integration.endpoint, held, { json: defaults[integration.endpoint] });
        await page.getByRole("button", { name: integration.nav, exact: true }).click();
        await expect(section(page, integration.name)).toHaveAttribute("data-state", "idle");
      },
    );
  }
  await scenario(
    "viewer can close fleet details when releases are unsupported",
    async ({ page, overrides, login }) => {
      overrides.set("/v1/me", { json: { subject: "viewer", roles: ["viewer"] } });
      overrides.set("/v1/releases", { status: 404, json: { error: "not_found" } });
      await login();
      await expect(fleet(page)).toBeVisible();
      await page.getByRole("button", { name: "Device fleet", exact: true }).click();
      await page.getByText(device.hostname, { exact: true }).click();
      await expect(page.getByRole("dialog")).toBeVisible();
      await page.getByRole("button", { name: "Close details", exact: true }).click();
      await expect(page.getByRole("dialog")).toHaveCount(0);
      await page.screenshot({ path: path.join(evidence, "loading-after.png"), fullPage: true });
    },
  );
  await scenario("unavailable counts fit a 390 pixel overview", async ({ page, overrides, login }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    overrides.set("/v1/jobs", { status: 503, json: { error: "unavailable" } });
    overrides.set("/v1/releases", { status: 404, json: { error: "not_found" } });
    await login();
    await expect(section(page, "Operations")).toHaveAttribute("data-state", "failed");
    await expect(section(page, "Releases")).toHaveAttribute("data-state", "unsupported");
    await expect(page.locator(".stat").filter({ hasText: "Active operations" }).locator("strong")).toHaveText(
      "Unavailable",
    );
    await page.evaluate(() => document.fonts.ready);
    const dimensions = await page.evaluate(() => ({
      viewport: window.innerWidth,
      document: document.documentElement.scrollWidth,
    }));
    assert.ok(dimensions.document <= dimensions.viewport, JSON.stringify(dimensions));
    await page.screenshot({ path: path.join(evidence, "loading-mobile-after.png"), fullPage: true });
  });
  console.log(`${results.length} rendered loading scenarios passed.`);
} finally {
  await writeFile(
    path.join(evidence, "loading-verdict.json"),
    `${JSON.stringify({ results, cacheDir }, null, 2)}\n`,
  );
  await browser.close();
  await server.close();
}
