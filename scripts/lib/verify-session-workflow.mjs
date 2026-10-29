import assert from "node:assert/strict";
import { expect } from "@playwright/test";

export async function verifySessionWorkflow({ page, fixture, device, hostname }) {
  const session = { sessionId: 7, userSid: "S-1-5-21-10-20-30-1001", logonId: "00000000abcdef12" };
  const headers = { authorization: `Bearer ${device.credential}` };
  const open = async (kind) => {
    await page.getByRole("button", { name: "New operation", exact: true }).click();
    const form = page.getByRole("dialog", { name: "Create an operation", exact: true });
    await form.getByLabel("Operation", { exact: true }).selectOption(kind);
    await form.getByLabel(hostname, { exact: true }).check();
    return form;
  };
  const submit = async (form) => {
    await form.getByRole("button", { name: "Create operation", exact: true }).click();
    await expect(form).toBeHidden();
    return (await fixture.agent("/v1/agent/native-claim", headers, {})).lease;
  };
  const listing = await submit(await open("sessions.list"));
  assert.equal(listing.command.kind, "sessions.list");
  // UI fixture only; real WTS collection is exercised separately by the SYSTEM-service pilot.
  await fixture.agent(`/v1/agent/native-jobs/${listing.id}/report`, headers, {
    leaseToken: listing.leaseToken,
    state: "succeeded",
    result: {
      partial: false,
      sessions: [
        {
          ...session,
          user: "FixtureUser",
          domain: "FIXTURE",
          station: "RDP-Tcp#1",
          state: "active",
          selectable: true,
        },
      ],
    },
  });
  await page.getByRole("button", { name: "Update operations", exact: true }).click();
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  const form = await open("applications.check");
  await expect(form.getByLabel("User session").getByRole("option", { name: /FixtureUser/ })).toHaveCount(1);
  await form.getByLabel("User session").selectOption(JSON.stringify(session));
  const checked = await submit(form);
  assert.equal(checked.command.kind, "applications.check");
  assert.deepEqual(checked.command.session, session);
  await fixture.agent(`/v1/agent/native-jobs/${checked.id}/report`, headers, {
    leaseToken: checked.leaseToken,
    state: "failed",
    result: { reason: "selected_user_provider_unavailable", executionStarted: false, session },
  });
  await page.getByRole("button", { name: "Update operations", exact: true }).click();
}
