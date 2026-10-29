// SPDX-License-Identifier: GPL-3.0-only
// Adapted from TIBCON Sentry; original license retained.
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import type { TransactionQuery } from "../../../apps/control-plane/src/database.js";
import { ApiError } from "../../../apps/control-plane/src/security.js";

const eventSchema = z.strictObject({
  eventId: z.string().min(1).max(255),
  eventType: z.string().min(1).max(120),
  sentAt: z.iso.datetime(),
  occurredAt: z.iso.datetime(),
  event: z.record(z.string(), z.json()),
});
export function authenticatedFalconEvent(raw: Buffer, header: unknown, secret: string | undefined) {
  if (!secret) throw new ApiError(503, "falcon_webhook_unconfigured");
  const signature = typeof header === "string" ? header.replace(/^sha256=/, "").trim() : "";
  if (!/^[a-fA-F0-9]{64}$/.test(signature)) throw new ApiError(401, "invalid_webhook_signature");
  const expected = createHmac("sha256", secret).update(raw).digest();
  if (!timingSafeEqual(expected, Buffer.from(signature, "hex")))
    throw new ApiError(401, "invalid_webhook_signature");
  return {
    body: eventSchema.parse(JSON.parse(raw.toString("utf8"))),
    digest: createHash("sha256").update(raw).digest("hex"),
  };
}
export async function ingestFalconEvent(
  tx: TransactionQuery,
  scope: string,
  authenticated: ReturnType<typeof authenticatedFalconEvent>,
) {
  const { body, digest } = authenticated;
  const [prior] = await tx.query<{ body_sha256: string }>(
    "SELECT body_sha256 FROM falcon_events WHERE scope_id=$1 AND event_id=$2",
    [scope, body.eventId],
  );
  if (prior) {
    if (prior.body_sha256 !== digest) throw new ApiError(409, "webhook_event_conflict");
    return { accepted: true, duplicate: true };
  }
  const [time] = await tx.query<{ fresh: boolean }>(
    "SELECT abs(extract(epoch from(clock_timestamp()-$1::timestamptz)))<=300 AND $2::timestamptz<=clock_timestamp()+interval '5 minutes' AS fresh",
    [body.sentAt, body.occurredAt],
  );
  if (!time?.fresh) throw new ApiError(400, "webhook_timestamp_outside_window");
  const aid = body.event.aid ?? body.event.device_id ?? body.event.sensor_id ?? body.event.AgentIdString;
  await tx.query(
    "INSERT INTO falcon_events(scope_id,event_id,body_sha256,event_type,aid,payload,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
    [
      scope,
      body.eventId,
      digest,
      body.eventType,
      typeof aid === "string" ? aid : null,
      JSON.stringify(body.event),
      body.occurredAt,
    ],
  );
  return { accepted: true, duplicate: false };
}
