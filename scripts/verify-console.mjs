import { mkdirSync } from "node:fs";
import { chromium, expect } from "@playwright/test";
import { consoleNativeFixture } from "./lib/console-native-fixture.mjs";
import { verifyOperationalWorkflows } from "./lib/verify-console-workflows.mjs";

// Local-only acceptance exercise. It does not install an agent or execute an OS update.
const fixture = await consoleNativeFixture();
const { apiOrigin, consoleOrigin, env } = fixture;
const hostname = `LOCAL-QA-${Date.now()}`;
const browser = await chromium.launch({ headless: true });
const errors = [];
browser.on("page", (page) => page.on("pageerror", (error) => errors.push(error.name)));
let deviceId;
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1060 } });
  await page.goto(consoleOrigin);
  await page.getByLabel("Local development access token").fill(env.DEV_OPERATOR_TOKEN);
  await page.getByRole("button", { name: "Open operations console" }).click();
  await expect(page.getByRole("heading", { name: "Fleet overview", exact: true })).toBeVisible();
  mkdirSync(".local/screenshots", { recursive: true });
  await page.screenshot({ path: ".local/screenshots/overview-desktop.png", fullPage: true });
  await page.getByRole("button", { name: "Device fleet", exact: true }).click();
  await page.getByRole("button", { name: "Enroll computer", exact: true }).click();
  await page.getByRole("combobox", { name: /^Management scope/ }).selectOption(fixture.scopeId);
  await page.getByLabel("Computer name").fill(hostname);
  await page.getByLabel("Machine identity").fill(`windows:${crypto.randomUUID()}`);
  await page.getByRole("button", { name: "Create native invitation" }).click();
  const token = await page.getByLabel("One-time invitation").inputValue();
  const device = await fixture.enroll(hostname, token);
  deviceId = device.deviceId;
  await page.getByRole("button", { name: "Close dialog", exact: true }).click();
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  await expect(page.getByRole("row").filter({ hasText: hostname }).first()).toBeVisible();
  await page.getByRole("button", { name: "New operation", exact: true }).click();
  await page.getByLabel(hostname, { exact: true }).check();
  await page.getByRole("button", { name: "Create operation", exact: true }).click();
  await expect(page.getByRole("button", { name: /Inventory refresh/ }).first()).toBeVisible();
  const headers = { "Content-Type": "application/json", authorization: `Bearer ${device.credential}` };
  const { lease } = await fixture.agent("/v1/agent/native-claim", headers, {});
  if (!lease) throw new Error("No inventory job dispatched");
  const inventory = {
    hostname,
    rebootPending: false,
    testFixture: true,
    agentVersion: "0.2.2.0",
    agentRecoveryReady: true,
    osVersion: "Microsoft Windows 11 (acceptance fixture)",
    displayVersion: "25H2",
    architecture: "X64",
    collectedAt: new Date().toISOString(),
    collection: {
      schemaVersion: 2,
      status: "partial",
      applicationScope: "machine_registry_32_and_64_bit",
      issues: [{ section: "hardware.disks", code: "unavailable" }],
    },
    hardware: {
      manufacturer: "Console acceptance fixture",
      model: "Virtual test computer",
      processor: "Acceptance processor",
      logicalProcessors: 8,
      memory: { totalBytes: 16 * 1024 ** 3, availableBytes: 4 * 1024 ** 3 },
      uptimeSeconds: 90_000,
      disks: [
        {
          name: "C:\\",
          fileSystem: "NTFS",
          systemVolume: true,
          status: "available",
          totalBytes: 500 * 1024 ** 3,
          freeBytes: 20 * 1024 ** 3,
        },
        {
          name: "D:\\",
          fileSystem: null,
          systemVolume: false,
          status: "unavailable",
          totalBytes: null,
          freeBytes: null,
        },
      ],
    },
    applications: [{ name: "Acceptance application", version: "1.0.0", publisher: "Console QA fixture" }],
  };
  await fixture.agent(`/v1/agent/native-jobs/${lease.id}/report`, headers, {
    leaseToken: lease.leaseToken,
    state: "succeeded",
    result: inventory,
  });
  await fixture.seedPresentationInventory(deviceId, inventory);
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  await expect(
    page.getByRole("row").filter({ hasText: hostname }).getByText("Succeeded", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Audit trail", exact: true }).click();
  await page.getByRole("button", { name: "Device fleet", exact: true }).click();
  await expect(
    page
      .getByRole("row")
      .filter({ hasText: hostname })
      .getByRole("cell", { name: /^0\.2\.2\.0/ }),
  ).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "CRM registration", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Audit trail", exact: true }).click();
  await expect(page.getByRole("row").filter({ hasText: "native.job_reported" }).first()).toBeVisible();
  const operatorHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${env.DEV_OPERATOR_TOKEN}`,
  };
  const secondDevice = await fixture.enroll(`${hostname}-SECOND`);
  const created = await fetch(`${apiOrigin}/v1/batches`, {
    method: "POST",
    headers: { ...operatorHeaders, "Idempotency-Key": crypto.randomUUID() },
    body: JSON.stringify({
      targets: [deviceId, secondDevice.deviceId],
      ring: "canary",
      command: {
        kind: "windows.install",
        updates: [{ id: "f7c4f8bf-f195-4c5b-ae35-91535c7bbf84", revision: 7 }],
      },
      startsAt: new Date(Date.now() - 1000).toISOString(),
      endsAt: new Date(Date.now() + 3600_000).toISOString(),
    }),
  });
  if (!created.ok) throw new Error("Review fixture batch failed");
  const approverPage = await browser.newPage({ viewport: { width: 1440, height: 1060 } });
  await approverPage.goto(consoleOrigin);
  await approverPage.getByLabel("Local development access token").fill(env.DEV_APPROVER_TOKEN);
  await approverPage.getByRole("button", { name: "Open operations console" }).click();
  await approverPage.getByRole("button", { name: "Update operations", exact: true }).click();
  await approverPage
    .getByRole("row")
    .filter({ hasText: hostname })
    .filter({ hasText: "Awaiting approval" })
    .first()
    .getByRole("button", { name: "Review batch", exact: true })
    .click();
  const review = approverPage.getByRole("dialog", { name: "Review installation batch" });
  await expect(review.getByText("f7c4f8bf-f195-4c5b-ae35-91535c7bbf84", { exact: false })).toBeVisible();

  await expect(review.getByRole("row")).toHaveCount(3);
  const approveButton = review.getByRole("button", { name: "Approve reviewed batch" });
  await expect(approveButton).toBeDisabled();
  await review.getByRole("checkbox").check();
  await approverPage.screenshot({ path: ".local/screenshots/approval-review-desktop.png", fullPage: true });
  await approverPage.setViewportSize({ width: 390, height: 844 });
  await approverPage.screenshot({ path: ".local/screenshots/approval-review-mobile.png", fullPage: true });
  if (await approverPage.evaluate(() => document.documentElement.scrollWidth > window.innerWidth))
    throw new Error("Approval review mobile overflow");
  await approveButton.click();
  await expect(review).toBeHidden();
  await approverPage.close();
  await verifyOperationalWorkflows({
    page,
    browser,
    env,
    device,
    secondDevice,
    hostname,
    operatorHeaders,
    fixture,
    apiOrigin,
    consoleOrigin,
  });
  // Hold an authorised refresh across sign-out, then deliver its old response.
  let releaseOldResponse;
  let responseHeld;
  const held = new Promise((resolve) => {
    responseHeld = resolve;
  });
  const release = new Promise((resolve) => {
    releaseOldResponse = resolve;
  });
  await page.route(
    "**/v1/me",
    async (route) => {
      const response = await route.fetch();
      responseHeld();
      await release;
      await route.fulfill({ response }).catch(() => undefined); // Browser may have cancelled this route.
    },
    { times: 1 },
  );
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  await held;
  await page.getByRole("button", { name: /Sign out/ }).click();
  await expect(page.getByLabel("Local development access token")).toBeVisible();
  releaseOldResponse();
  await page.waitForLoadState("networkidle");
  await expect(page.getByRole("heading", { name: "Fleet overview", exact: true })).toBeHidden();
  await expect(page.getByText(hostname, { exact: true })).toBeHidden();
  await page.getByLabel("Local development access token").fill(env.DEV_OPERATOR_TOKEN);
  await page.getByRole("button", { name: "Open operations console" }).click();
  await expect(page.getByRole("heading", { name: "Fleet overview", exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Overview", exact: true }).click();
  await page.screenshot({ path: ".local/screenshots/overview-mobile.png", fullPage: true });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  if (errors.length || overflow) throw new Error("Console runtime error or mobile overflow");
  console.log(
    "Console verification passed: login, enrollment, structured inventory, guided Windows updates, evidence-backed reconciliation, independent approval, viewer isolation, stale-refresh/sign-out race protection and desktop/mobile layout.",
  );
} finally {
  await browser.close();
  await fixture.close();
}
