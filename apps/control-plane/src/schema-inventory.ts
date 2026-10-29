/** Every persisted table has an explicit restore disposition. New tables require a new schema version. */
export const v1Tables = [
  "schema_migrations",
  "devices",
  "enrollment_tokens",
  "credentials",
  "releases",
  "batches",
  "jobs",
  "audit_events",
  "idempotency_keys",
] as const;

export const authorityTables = {
  migration_metadata: "preserve",
  authority_runtime: "quarantine",
  management_scopes: "quarantine",
  scope_grants: "revoke",
  native_invitations: "consume",
  native_enrollments: "revoke",
  module_states: "disable",
} as const;
export const v2Tables = [...v1Tables, ...Object.keys(authorityTables)] as const;
export const desktopTables = {
  desktop_policies: "preserve-inert",
  desktop_policy_versions: "preserve",
  desktop_groups: "preserve-inert",
  desktop_assignments: "preserve-inert",
  desktop_fleets: "preserve-inert",
  desktop_policy_canaries: "abort",
  desktop_canary_targets: "preserve-evidence",
} as const;
export const v3Tables = [...v2Tables, ...Object.keys(desktopTables)] as const;
export const assetTables = {
  company_people: "preserve",
  managed_assets: "preserve",
  asset_links: "preserve-evidence",
} as const;
export const v4Tables = [...v3Tables, ...Object.keys(assetTables)] as const;
export const falconTables = {
  falcon_sync_state: "pause",
  falcon_cached_records: "preserve-evidence",
  falcon_events: "preserve-evidence",
} as const;
export const v5Tables = [...v4Tables, ...Object.keys(falconTables)] as const;
export const nativeTables = {
  native_custody_records: "preserve-evidence",
  native_publisher_evidence: "preserve-evidence",
  native_publication_sequences: "preserve",
  native_publications: "quarantine",
  native_catalog_heads: "clear",
  native_selections: "preserve-inert",
  native_policy_heads: "clear",
  native_nonce_receipts: "quarantine",
} as const;
export const v6Tables = [...v5Tables, ...Object.keys(nativeTables)] as const;
export const observationTables = {
  native_report_streams: "preserve-inert",
  native_observations: "preserve-evidence",
} as const;
export const v7Tables = [...v6Tables, ...Object.keys(observationTables)] as const;
export const nativeJobTables = {
  native_job_admissions: "preserve-inert",
  native_job_claims: "quarantine",
  native_job_receipts: "preserve-evidence",
} as const;
export const v8Tables = [...v7Tables, ...Object.keys(nativeJobTables)] as const;
export const recoveryTables = { recovery_key_escrow: "preserve-encrypted" } as const;
export const v9Tables = [...v8Tables, ...Object.keys(recoveryTables)] as const;
export const v10Tables = v9Tables;
export const schemaVersions = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] as const;

export function tablesForVersions(versions: readonly number[]): readonly string[] {
  if (JSON.stringify(versions) === "[1]") return v1Tables;
  if (JSON.stringify(versions) === "[1,2]") return v2Tables;
  if (JSON.stringify(versions) === "[1,2,3]") return v3Tables;
  if (JSON.stringify(versions) === "[1,2,3,4]") return v4Tables;
  if (JSON.stringify(versions) === "[1,2,3,4,5]") return v5Tables;
  if (JSON.stringify(versions) === "[1,2,3,4,5,6]") return v6Tables;
  if (JSON.stringify(versions) === "[1,2,3,4,5,6,7]") return v7Tables;
  if (JSON.stringify(versions) === "[1,2,3,4,5,6,7,8]") return v8Tables;
  if (JSON.stringify(versions) === "[1,2,3,4,5,6,7,8,9]") return v9Tables;
  if (JSON.stringify(versions) === "[1,2,3,4,5,6,7,8,9,10]") return v10Tables;
  throw new Error("Unsupported database schema version");
}
