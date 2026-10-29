import type { TransactionQuery } from "./database.js";

/** Runs only inside an isolated restore transaction, before a destination is published. */
export async function quarantineLegacy(tx: TransactionQuery) {
  const jobs = (
    await tx.query(
      "UPDATE jobs SET state='indeterminate', lease_hash=NULL, lease_expires_at=NULL, finished_at=clock_timestamp(), result=jsonb_build_object('status','indeterminate','summary','Restored snapshot requires explicit reconciliation; execution after capture is unknown') WHERE state IN ('awaiting_approval','queued','leased') RETURNING id",
    )
  ).length;
  const credentials = (
    await tx.query(
      "UPDATE credentials SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL RETURNING hash",
    )
  ).length;
  const enrollments = (
    await tx.query(
      "UPDATE enrollment_tokens SET used_at=clock_timestamp() WHERE used_at IS NULL RETURNING hash",
    )
  ).length;
  return { jobs, credentials, enrollments };
}

export async function quarantineAuthority(tx: TransactionQuery) {
  await tx.query("UPDATE native_job_claims SET state='quarantined'");
  await tx.query("DELETE FROM native_policy_heads");
  await tx.query("DELETE FROM native_catalog_heads");
  await tx.query("UPDATE native_publications SET state='quarantined'");
  await tx.query("UPDATE native_nonce_receipts SET state='quarantined'");
  await tx.query(
    "UPDATE falcon_sync_state SET status='paused',cursor=NULL,error_code=NULL WHERE status IN ('running','error')",
  );
  const policyCanaries = (
    await tx.query(
      "UPDATE desktop_policy_canaries SET state='aborted',finished_at=clock_timestamp() WHERE state IN ('pending','healthy') RETURNING id",
    )
  ).length;
  await tx.query("UPDATE authority_runtime SET state='quarantined'");
  const scopes = (
    await tx.query(
      "UPDATE management_scopes SET state='quarantined' WHERE state <> 'quarantined' RETURNING id",
    )
  ).length;
  const grants = (
    await tx.query(
      "UPDATE scope_grants SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL RETURNING scope_id",
    )
  ).length;
  const invitations = (
    await tx.query(
      "UPDATE native_invitations SET used_at=clock_timestamp() WHERE used_at IS NULL RETURNING hash",
    )
  ).length;
  const nativeEnrollments = (
    await tx.query(
      "UPDATE native_enrollments SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL RETURNING id",
    )
  ).length;
  const modules = (
    await tx.query("UPDATE module_states SET state='disabled' WHERE state <> 'disabled' RETURNING module_id")
  ).length;
  return { scopes, grants, invitations, nativeEnrollments, modules, policyCanaries };
}

export async function verifyQuarantine(tx: TransactionQuery): Promise<void> {
  const [row] = await tx.query<{ safe: boolean }>(`SELECT
    (SELECT count(*)=1 AND bool_and(state='quarantined') FROM authority_runtime)
    AND NOT EXISTS (SELECT 1 FROM jobs WHERE state IN ('awaiting_approval','queued','leased'))
    AND NOT EXISTS (SELECT 1 FROM credentials WHERE revoked_at IS NULL)
    AND NOT EXISTS (SELECT 1 FROM enrollment_tokens WHERE used_at IS NULL)
    AND NOT EXISTS (SELECT 1 FROM management_scopes WHERE state <> 'quarantined')
    AND NOT EXISTS (SELECT 1 FROM scope_grants WHERE revoked_at IS NULL)
    AND NOT EXISTS (SELECT 1 FROM native_invitations WHERE used_at IS NULL)
    AND NOT EXISTS (SELECT 1 FROM native_enrollments WHERE revoked_at IS NULL)
    AND NOT EXISTS (SELECT 1 FROM module_states WHERE state <> 'disabled')
    AND NOT EXISTS (SELECT 1 FROM desktop_policy_canaries WHERE state IN ('pending','healthy'))
    AND NOT EXISTS (SELECT 1 FROM falcon_sync_state WHERE status IN ('running','error'))
    AND NOT EXISTS (SELECT 1 FROM native_publications WHERE state<>'quarantined')
    AND NOT EXISTS (SELECT 1 FROM native_nonce_receipts WHERE state<>'quarantined')
    AND NOT EXISTS (SELECT 1 FROM native_job_claims WHERE state<>'quarantined')
    AND NOT EXISTS (SELECT 1 FROM native_policy_heads)
    AND NOT EXISTS (SELECT 1 FROM native_catalog_heads) AS safe`);
  if (row?.safe !== true) throw new Error("Restored authority was not quarantined");
}
