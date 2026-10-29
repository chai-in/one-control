const messages: Record<string, string> = {
  native_custody_unconfigured:
    "An administrator must configure signing custody before publishing native modules.",
  native_custody_inactive: "Native signing custody is not active for this workspace.",
  native_custody_unavailable: "The configured native signing keys could not be loaded.",
  native_catalog_unavailable: "Publish a current catalog and save this platform's selection against it.",
  native_selection_unconfigured: "This platform does not yet have a saved module selection.",
  native_publication_superseded:
    "The scope or catalog changed during signing. Refresh before publishing again.",
  native_publisher_evidence_missing: "The catalog bundle is missing a required publisher attestation.",
  native_publisher_evidence_expired: "The publisher evidence expires before this catalog can be used.",
  native_permission_not_granted: "The selection requests a permission outside this scope's ceiling.",
  native_user_session_required: "This operation requires a protected user-session host.",
  native_job_admission_missing:
    "This job has no current native enrollment admission. Create a new reviewed job.",
  native_terminal_conflict: "A different terminal result has already been recorded for this operation.",
  recent_multifactor_authentication_required:
    "Verify your sign-in with multifactor authentication, then reveal the key again within five minutes.",
  recovery_escrow_unconfigured:
    "An administrator must configure the recovery encryption keyring before storing keys.",
  recovery_escrow_unavailable: "The recovery encryption keyring could not be loaded.",
  recovery_escrow_key_unavailable: "This recovery key needs a retained encryption key that is not loaded.",
  recovery_escrow_integrity_failed: "The encrypted recovery record could not be authenticated.",
  recovery_key_backup_disabled: "Enable recovery-key backup in this computer's assigned desktop policy.",
  scope_version_conflict: "This scope changed. Refresh before making another change.",
  scope_forbidden: "Your identity has not been granted this operation in the selected scope.",
  scope_unavailable: "This scope is revoked or quarantined.",
  authority_quarantined: "This restored workspace requires authority recovery before management resumes.",
  module_disabled: "Enable this module in the selected scope before using it.",
  integration_scope_unconfigured: "The server has not bound these integration credentials to this scope.",
  company_monitoring_only: "Application activity and screenshots are available only in company scopes.",
  policy_in_use: "Remove device, group and default assignments before deleting this policy.",
  policy_id_retired: "This policy ID is retired. Choose a new ID; its history is retained.",
  abort_policy_canary_before_editing: "Abort the active canary before editing or retiring its policy.",
  canary_target_policy_mismatch: "Every selected device must inherit or override to the canary's policy.",
  canary_verified_health_required:
    "All canary targets need verified health for this exact candidate before promotion.",
  canary_base_changed: "The live policy changed after staging. Abort and stage a new canary.",
  canary_terminal: "This canary has already ended. Refresh its current state.",
  falcon_scope_denied: "The Falcon API account lacks permission for this resource.",
  falcon_unlicensed: "The Falcon tenant does not license this resource.",
  falcon_rate_limited: "Falcon is rate limiting requests. Wait before requesting another page.",
  falcon_incomplete_response:
    "Falcon returned an incomplete result. It is not being shown as a complete inventory.",
  database_commit_unknown:
    "The database outcome is unknown. Inspect the current state before submitting another change.",
  invalid_request: "Check the required fields and the maintenance window, then try again.",
  separate_approver_required: "A different authorised person must approve this installation batch.",
  previous_ring_not_successful:
    "The same operation must finish successfully in the previous rollout ring first.",
  batch_not_approvable:
    "This batch has changed, expired, or already been handled. Refresh its current state.",
  batch_review_changed: "The batch no longer matches this review. Open a fresh review before approving.",
  already_approved: "Another approver has already approved this batch. Refresh to see its current state.",
  device_has_unfinished_jobs:
    "Finish, cancel or reconcile this computer’s outstanding operations before changing its ring.",
  agent_recovery_unavailable:
    "Every target needs a running independent recovery service before an agent update can be scheduled.",
  poc_canary_only:
    "This workspace is a limited POC. Pilot and broad rollouts are disabled until deployment approval.",
  poc_device_limit_reached:
    "The POC has reached its active-computer limit. Revoke a retired test computer before enrolling another.",
  maintenance_window_expired: "The maintenance window has ended. Choose a new start and end time.",
  job_not_indeterminate: "This operation no longer needs reconciliation. Refresh its current result.",
  invalid_targets_or_ring:
    "Some selected computers are revoked or belong to another ring. Refresh the fleet and select again.",
  forbidden: "Your current role does not allow this action.",
  falcon_unavailable:
    "Falcon could not be reached. Its API credentials stay on the control plane; IT can check the connection there.",
  ema_unavailable: "Intel EMA could not be reached. IT can check its server connection and credentials.",
};
export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}
export function apiError(code: unknown) {
  return typeof code === "string"
    ? (messages[code] ?? `The request could not be completed (${code.replaceAll("_", " ")}).`)
    : "The request could not be completed. Refresh the current state before retrying a change.";
}
