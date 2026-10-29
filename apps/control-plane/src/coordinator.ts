import { type Command, isMutation } from "@one-control/protocol";
import type { Database, TransactionQuery } from "./database.js";
import { audit } from "./routes/context.js";

// Callers hold the device row lock. All dispatch, revocation and reconciliation use the same lock order.
export async function reconcileDeviceJobs(tx: TransactionQuery, deviceId: string, allowReadRetry = false) {
  const expired = await tx.query<{ id: string; command: Command; attempt: number }>(
    "SELECT id,command,attempt FROM jobs WHERE device_id=$1 AND state='leased' AND lease_expires_at<=now() FOR UPDATE",
    [deviceId],
  );
  for (const job of expired) {
    const state = isMutation(job.command)
      ? "indeterminate"
      : !allowReadRetry || job.attempt >= 3
        ? "failed"
        : "queued";
    await tx.query(
      "UPDATE jobs SET state=$1,lease_hash=NULL,lease_expires_at=NULL,result=$2,finished_at=CASE WHEN $1='queued' THEN NULL ELSE now() END WHERE id=$3",
      [state, JSON.stringify({ reason: "lease_expired" }), job.id],
    );
    await audit(tx, "coordinator", "job.lease_expired", job.id, { state });
  }
  const cancelled = await tx.query<{ id: string }>(
    "UPDATE jobs SET state='cancelled',finished_at=now() WHERE device_id=$1 AND state IN ('queued','awaiting_approval') AND ends_at<=now() RETURNING id",
    [deviceId],
  );
  for (const job of cancelled) await audit(tx, "coordinator", "job.window_expired", job.id);
}

export async function reconcileExpiredJobs(db: Database): Promise<number> {
  return db.transaction(async (tx) => {
    const [runtime] = await tx.query<{ state: string }>(
      "SELECT state FROM authority_runtime WHERE singleton=true FOR SHARE",
    );
    if (runtime?.state === "quarantined") return 0;
    const candidates = await tx.query<{ id: string }>(`SELECT d.id FROM devices d WHERE EXISTS(
      SELECT 1 FROM jobs j WHERE j.device_id=d.id AND
      ((j.state='leased' AND j.lease_expires_at<=now()) OR
       (j.state IN ('queued','awaiting_approval') AND j.ends_at<=now())))
      ORDER BY d.id LIMIT 100`);
    if (!candidates.length) return 0;
    const ids = candidates.map((device) => device.id);
    const scopes = await tx.query<{ scope_id: string }>(
      "SELECT DISTINCT scope_id FROM native_enrollments WHERE device_id=ANY($1::uuid[]) ORDER BY scope_id",
      [ids],
    );
    for (const scope of scopes)
      await tx.query("SELECT id FROM management_scopes WHERE id=$1 FOR UPDATE", [scope.scope_id]);
    const devices = await tx.query<{ id: string }>(
      "SELECT id FROM devices WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE SKIP LOCKED",
      [ids],
    );
    for (const device of devices) await reconcileDeviceJobs(tx, device.id);
    return devices.length;
  });
}
