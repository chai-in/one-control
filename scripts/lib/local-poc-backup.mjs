import { lstatSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const backupCapability = "database-backup-v1";
export const backupId = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export function backupRequest(value, runId, now = Date.now()) {
  if (
    !value ||
    Object.keys(value).sort().join(",") !== "createdAt,expiresAt,requestId,runId,schemaVersion" ||
    value.schemaVersion !== 1 ||
    typeof value.requestId !== "string" ||
    typeof value.runId !== "string" ||
    typeof value.createdAt !== "string" ||
    typeof value.expiresAt !== "string" ||
    !backupId.test(value.requestId) ||
    value.runId !== runId ||
    !backupId.test(runId)
  )
    return null;
  const created = Date.parse(value.createdAt);
  const expires = Date.parse(value.expiresAt);
  if (
    !Number.isFinite(created) ||
    !Number.isFinite(expires) ||
    created > now ||
    expires <= now ||
    expires - created > 120_000 ||
    expires <= created
  )
    return null;
  return value;
}
export function backupDirectory(root, name) {
  if (!["backups", "backup-requests", "restores"].includes(name))
    throw new Error("Unexpected backup storage type");
  const directory = join(root, name);
  try {
    mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink())
    throw new Error("Backup storage cannot be a link or file");
  return directory;
}
export function pendingBackupRequests(root, runId, handled, now = Date.now()) {
  const directory = backupDirectory(root, "backup-requests");
  const entries = readdirSync(directory);
  if (entries.length > 1000) throw new Error("Backup request history requires administrator maintenance");
  const requests = [];
  for (const name of entries.sort()) {
    if (!name.endsWith(".json") || !backupId.test(name.slice(0, -5)) || handled.has(name)) continue;
    const path = join(directory, name);
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024)
      throw new Error("Invalid protected backup request file");
    const value = backupRequest(JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, "")), runId, now);
    if (value?.requestId === name.slice(0, -5)) requests.push(value);
  }
  return requests;
}
