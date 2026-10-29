import assert from "node:assert/strict";
import { expect } from "@playwright/test";

export async function verifyIndexingWorkflow({ page, fixture, device, hostname }) {
  await page.getByRole("button", { name: "New operation", exact: true }).click();
  const form = page.getByRole("dialog", { name: "Create an operation", exact: true });
  await form.getByLabel("Operation", { exact: true }).selectOption("indexing.status");
  await form.getByLabel(hostname, { exact: true }).check();
  await form.getByRole("button", { name: "Create operation", exact: true }).click();
  await expect(form).toBeHidden();
  const headers = { authorization: `Bearer ${device.credential}` };
  const { lease } = await fixture.agent("/v1/agent/native-claim", headers, {});
  assert.equal(lease.command.kind, "indexing.status");
  await fixture.agent(`/v1/agent/native-jobs/${lease.id}/report`, headers, {
    leaseToken: lease.leaseToken,
    state: "succeeded",
    result: {
      after: {
        supported: true,
        service: "running",
        startup: "automatic-delayed",
        catalog: { status: "idle", items: 2048 },
        locationScope: "configured-rules",
        locations: [{ pattern: "file:///C:/AcceptanceFixture/*", included: true, default: false }],
        pauseMechanism: "service-stop-fallback",
      },
    },
  });
  await page.getByRole("button", { name: "Update operations", exact: true }).click();
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  await page
    .getByRole("row")
    .filter({ hasText: lease.id.slice(0, 8) })
    .getByRole("button", { name: "View receipt" })
    .click();
  const receipt = page.getByRole("dialog", { name: "Windows Search status", exact: true });
  await expect(receipt.getByText("idle", { exact: true })).toBeVisible();
  await expect(receipt.getByText("automatic-delayed", { exact: true })).toBeVisible();
  await expect(
    receipt.getByRole("cell", { name: "file:///C:/AcceptanceFixture/*", exact: true }),
  ).toBeVisible();
  await receipt.getByRole("button", { name: "Close details", exact: true }).click();
}
