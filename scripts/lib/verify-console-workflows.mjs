import assert from "node:assert/strict";
import { expect } from "@playwright/test";
// Every identity used here is created by the caller in the isolated local development API.
// No Windows service or update provider participates in this browser acceptance exercise.
export async function verifyOperationalWorkflows({
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
}) {
  async function call(path, headers, body) {
    if (path.startsWith("/v1/agent/native-")) return fixture.agent(path, headers, body);
    const response = await fetch(`${apiOrigin}${path}`, {
      method: body ? "POST" : "GET",
      headers,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!response.ok) throw new Error(`Console fixture request failed: ${path} (${response.status})`);
    return response.json();
  }
  const agentHeaders = { "Content-Type": "application/json", authorization: `Bearer ${device.credential}` };
  const { lease } = await call("/v1/agent/native-claim", agentHeaders, {});
  assert.equal(lease?.command.kind, "windows.install");
  await call(`/v1/agent/native-jobs/${lease.id}/report`, agentHeaders, {
    leaseToken: lease.leaseToken,
    state: "indeterminate",
    result: { testFixture: true, reason: "console_fixture_no_provider_executed" },
  });
  await page.getByRole("button", { name: "Update operations", exact: true }).click();
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  const uncertainRow = page.getByRole("row").filter({ hasText: lease.id.slice(0, 8) });
  await expect(uncertainRow.getByText("Needs reconciliation", { exact: true })).toBeVisible();
  await uncertainRow.getByRole("button", { name: "Review outcome" }).click();
  const receipt = page.getByRole("dialog", { name: "Windows Update install", exact: true });
  await receipt.getByRole("button", { name: "Record a verified outcome" }).click();
  const save = receipt.getByRole("button", { name: "Save verified outcome" });
  await expect(save).toBeDisabled();
  await receipt
    .getByLabel("What did you verify on the computer?")
    .fill(
      "Isolated browser acceptance fixture: no provider or installer was executed; the fixture reports a failed outcome for reconciliation testing.",
    );
  await expect(save).toBeDisabled();
  await receipt.getByRole("checkbox").check();
  await page.screenshot({ path: ".local/screenshots/reconciliation-desktop.png", fullPage: true });
  await save.click();
  await expect(receipt).toBeHidden();
  await expect(uncertainRow.getByText("Failed", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Device fleet", exact: true }).click();
  const deviceRow = page.getByRole("row").filter({ hasText: device.deviceId.slice(0, 8) });
  await page.getByLabel("Filter devices by attention").selectOption("low_space");
  await expect(deviceRow).toBeVisible();
  await page.getByLabel("Filter devices by attention").selectOption("recovery");
  await expect(deviceRow).toBeHidden();
  await page.getByLabel("Filter devices by attention").selectOption("all");
  await deviceRow.getByRole("button").click();
  const details = page.getByRole("dialog", { name: hostname, exact: true });
  await expect(details.getByText("Independent recovery", { exact: true })).toBeVisible();
  await expect(details.getByText("Partial inventory", { exact: true })).toBeVisible();
  await expect(details.getByText("16 GiB total", { exact: false })).toBeVisible();
  await expect(details.getByText("Less than 10% free space", { exact: true })).toBeVisible();
  await expect(details.getByText("Capacity unavailable at collection.", { exact: true })).toBeVisible();
  await expect(page.locator("body")).toHaveCSS("overflow-y", "hidden");
  await details.getByLabel("Search installed applications").fill("Acceptance application");
  await expect(details.getByRole("cell", { name: "Acceptance application", exact: true })).toBeVisible();
  await details.getByLabel("Search installed applications").fill("A-package-that-is-not-installed");
  await expect(details.getByText("No applications match your search.", { exact: true })).toBeVisible();
  await details.getByLabel("Search installed applications").fill("");
  await details.getByRole("heading", { name: "Hardware & capacity", exact: true }).scrollIntoViewIfNeeded();
  await details.screenshot({ path: ".local/screenshots/device-hardware-desktop.png" });
  await page.screenshot({ path: ".local/screenshots/device-details-desktop.png", fullPage: true });
  for (let index = 0; index < 3; index++) await page.keyboard.press("Shift+Tab");
  assert.equal(await details.evaluate((element) => element.matches(":modal")), true);
  // Native modal dialogs make the rest of the document inert. Browser chrome can
  // still receive keyboard focus, so check document isolation without cycling into it.
  await page.evaluate(() => document.querySelector("main button")?.focus());
  assert.equal(
    await page.evaluate(() => Boolean(document.activeElement?.closest("dialog"))),
    true,
    "Dialog focus escaped",
  );
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await expect(details).toBeVisible();
  await details.getByText("Less than 10% free space", { exact: true }).scrollIntoViewIfNeeded();
  await details.screenshot({ path: ".local/screenshots/device-capacity-mobile.png" });
  await page.screenshot({ path: ".local/screenshots/device-details-mobile.png", fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1060 });
  await details.getByRole("button", { name: "Close details", exact: true }).click();
  await expect(deviceRow.getByRole("button")).toBeFocused();
  await expect(page.locator("body")).not.toHaveCSS("overflow-y", "hidden");
  await deviceRow.getByRole("button").click();
  await details.getByRole("button", { name: "Scan Windows updates" }).click();
  const operation = page.getByRole("dialog", { name: "Create an operation", exact: true });
  await expect(operation.getByLabel("Operation", { exact: true })).toHaveValue("windows.scan");
  await expect(operation.getByRole("checkbox", { name: hostname, exact: true })).toBeChecked();
  await operation.getByRole("button", { name: "Create operation", exact: true }).click();
  await expect(operation).toBeHidden();
  const { lease: scan } = await call("/v1/agent/native-claim", agentHeaders, {});
  assert.equal(scan?.command.kind, "windows.scan");
  const update = { id: crypto.randomUUID(), revision: 7, title: "Console acceptance security update" };
  await call(`/v1/agent/native-jobs/${scan.id}/report`, agentHeaders, {
    leaseToken: scan.leaseToken,
    state: "succeeded",
    result: { testFixture: true, updates: [update] },
  });
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  await page
    .getByRole("row")
    .filter({ hasText: scan.id.slice(0, 8) })
    .getByRole("button", { name: "View receipt" })
    .click();
  const scanDetails = page.getByRole("dialog", { name: "Windows Update scan", exact: true });
  await expect(scanDetails.getByText(update.title, { exact: true })).toBeVisible();
  await scanDetails.getByRole("button", { name: "Choose updates to install" }).click();
  await expect(operation.getByRole("button", { name: "Create operation", exact: true })).toBeDisabled();
  await operation.getByRole("checkbox", { name: /Console acceptance security update/ }).check();
  await page.screenshot({ path: ".local/screenshots/guided-update-desktop.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await expect(operation).toBeVisible();
  await page.screenshot({ path: ".local/screenshots/guided-update-mobile.png", fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1060 });
  const created = page.waitForResponse(
    (response) =>
      response.url() === `${new URL(page.url()).origin}/v1/batches` && response.request().method() === "POST",
  );
  await operation.getByRole("button", { name: "Create operation", exact: true }).click();
  const response = await created;
  assert.equal(response.status(), 201);
  const { batchId } = await response.json();
  const review = await call(`/v1/batches/${batchId}`, operatorHeaders);
  assert.deepEqual(review.command, {
    kind: "windows.install",
    updates: [{ id: update.id, revision: update.revision }],
  });
  assert.deepEqual(
    review.targets.map((value) => value.deviceId),
    [device.deviceId],
  );
  assert.equal(review.targets[0].state, "awaiting_approval");

  if (!env.DEV_VIEWER_TOKEN)
    throw new Error("Browser acceptance requires the optional separate DEV_VIEWER_TOKEN");
  const viewer = await browser.newPage({ viewport: { width: 1440, height: 1060 } });
  await viewer.goto(consoleOrigin);
  await viewer.getByLabel("Local development access token").fill(env.DEV_VIEWER_TOKEN);
  await viewer.getByRole("button", { name: "Open operations console" }).click();
  await expect(viewer.getByRole("heading", { name: "Fleet overview", exact: true })).toBeVisible();
  await expect(viewer.getByRole("button", { name: "New operation", exact: true })).toBeHidden();
  await expect(viewer.getByRole("button", { name: "Enroll computer", exact: true })).toBeHidden();
  await viewer.getByRole("button", { name: "Device fleet", exact: true }).click();
  await viewer
    .getByRole("row")
    .filter({ hasText: device.deviceId.slice(0, 8) })
    .getByRole("button")
    .click();
  const readOnlyDetails = viewer.getByRole("dialog", { name: hostname, exact: true });
  await expect(readOnlyDetails.getByRole("button", { name: "Scan Windows updates" })).toBeHidden();
  await expect(readOnlyDetails.getByText("Device management", { exact: true })).toBeHidden();
  await viewer.screenshot({ path: ".local/screenshots/viewer-details-desktop.png", fullPage: true });
  await viewer.close();

  // Deliver a stale authorised snapshot after a newer refresh. It must not restore a revoked fixture.
  await page.getByRole("button", { name: "Device fleet", exact: true }).click();
  let ready;
  let release;
  const held = new Promise((resolve) => {
    ready = resolve;
  });
  const resume = new Promise((resolve) => {
    release = resolve;
  });
  await page.route(
    "**/v1/devices",
    async (route) => {
      const old = await route.fetch();
      ready();
      await resume;
      await route.fulfill({ response: old });
    },
    { times: 1 },
  );
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  await held;
  await fixture.revoke(secondDevice.enrollmentId);
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  const revokedRow = page.getByRole("row").filter({ hasText: secondDevice.deviceId.slice(0, 8) });
  await expect(revokedRow).toBeHidden();
  release();
  await page.waitForLoadState("networkidle");
  await expect(revokedRow).toBeHidden();
  await expect(deviceRow).toBeVisible();
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
}
