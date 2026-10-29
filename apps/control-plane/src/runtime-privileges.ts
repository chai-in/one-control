import { v10Tables } from "./schema-inventory.js";

// Runtime may write application state, never migration history or schema. The
// deployment owner applies these grants after ordered migrations have committed.
const appendOnly = new Set([
  "audit_events",
  "releases",
  "desktop_policy_versions",
  "native_custody_records",
  "native_publisher_evidence",
  "native_observations",
  "native_job_receipts",
]);
const history = new Set(["schema_migrations", "migration_metadata"]);
const deletable = new Set(["desktop_groups", "asset_links", "managed_assets"]);
const quote = (identifier: string) => `"${identifier.replaceAll('"', '""')}"`;

export function runtimeGrants(namespace: string, role: string, available: readonly string[]) {
  const tables = new Set(available);
  const statements = [`GRANT USAGE ON SCHEMA ${quote(namespace)} TO ${quote(role)}`];
  for (const table of v10Tables) {
    if (!tables.has(table)) continue;
    const permissions = ["SELECT"];
    if (!history.has(table)) {
      if (table !== "authority_runtime") permissions.push("INSERT");
      if (!appendOnly.has(table)) permissions.push("UPDATE");
      if (deletable.has(table)) permissions.push("DELETE");
    }
    statements.push(
      `GRANT ${permissions.join(",")} ON ${quote(namespace)}.${quote(table)} TO ${quote(role)}`,
    );
  }
  if (tables.has("audit_events"))
    statements.push(
      `GRANT USAGE ON SEQUENCE ${quote(namespace)}.audit_events_sequence_seq TO ${quote(role)}`,
    );
  return statements;
}
