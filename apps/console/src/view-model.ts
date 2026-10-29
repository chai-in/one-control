import type { Device, Job, JobState } from "@one-control/protocol";

export type Audit = {
  sequence: number;
  actor: string;
  action: string;
  subject: string;
  detail?: Record<string, unknown>;
  created_at: string;
};
export type Release = {
  id: string;
  package_id: string;
  sequence: number;
  manifest: { version: string; expiresAt: string };
  created_at: string;
};
export const labels: Record<string, string> = {
  "inventory.scan": "Inventory refresh",
  "windows.scan": "Windows Update scan",
  "windows.install": "Windows Update install",
  "indexing.status": "Windows Search status",
  "indexing.enable": "Enable Windows Search",
  "indexing.disable": "Disable Windows Search",
  "indexing.pause": "Stop Windows Search temporarily",
  "indexing.resume": "Resume Windows Search service",
  "winget.upgrade": "WinGet application",
  "store.upgrade": "Microsoft Store application",
  "package.install": "Signed MSI application",
};
export const date = (value: string | null) =>
  value && Number.isFinite(Date.parse(value))
    ? new Date(value).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" })
    : "Not reported";
export const short = (value: string) => value.slice(0, 8);

export const jobStates: Record<JobState, { label: string; tone: string; description: string }> = {
  awaiting_approval: {
    label: "Awaiting approval",
    tone: "warning",
    description: "A separate approver must review this batch before it can run.",
  },
  queued: {
    label: "Scheduled",
    tone: "info",
    description: "Waiting for the maintenance window and an available computer.",
  },
  leased: {
    label: "Running",
    tone: "info",
    description: "The agent owns this operation and is reporting its progress.",
  },
  succeeded: {
    label: "Succeeded",
    tone: "good",
    description: "The agent reported a successful outcome. Review the result for details.",
  },
  failed: {
    label: "Failed",
    tone: "bad",
    description: "The operation did not succeed. Review its result before deciding what to do next.",
  },
  cancelled: {
    label: "Cancelled",
    tone: "muted",
    description: "This pending operation was cancelled before execution.",
  },
  indeterminate: {
    label: "Needs reconciliation",
    tone: "bad",
    description:
      "The result is uncertain. Further work on this computer is blocked until IT verifies the actual outcome.",
  },
};

export function connection(device: Device, now = Date.now()) {
  if (device.revoked_at) return { label: "Revoked", tone: "muted" };
  if (device.last_seen_at && now - Date.parse(device.last_seen_at) < 120_000)
    return { label: "Online", tone: "good" };
  return { label: "Offline", tone: "muted" };
}

export function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function text(value: unknown, fallback = "Not reported") {
  return typeof value === "string" && value.trim() ? value : fallback;
}

export function relativeTime(value: string | null, now = Date.now()) {
  if (!value || !Number.isFinite(Date.parse(value))) return "Not reported";
  const minutes = Math.max(0, Math.floor((now - Date.parse(value)) / 60_000));
  if (minutes === 0) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
  return `${Math.floor(minutes / 1440)}d ago`;
}

export function applications(inventory: Record<string, unknown> | null) {
  const values = inventory?.applications;
  if (!Array.isArray(values)) return [];
  const unique = new Map<string, { name: string; version: string; publisher: string }>();
  for (const app of values.flatMap((value) => {
    const app = record(value);
    return app && typeof app.name === "string" && app.name.trim()
      ? [{ name: app.name, version: text(app.version, "—"), publisher: text(app.publisher, "—") }]
      : [];
  }))
    unique.set(JSON.stringify([app.name, app.version, app.publisher]), app);
  return [...unique.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export type AvailableUpdate = { id: string; revision: number; title: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function availableUpdates(result: Record<string, unknown> | null): AvailableUpdate[] {
  if (!Array.isArray(result?.updates) || result.partial === true) return [];
  const found = new Map<string, AvailableUpdate>();
  for (const value of result.updates) {
    const update = record(value);
    if (
      !update ||
      typeof update.id !== "string" ||
      !uuid.test(update.id) ||
      typeof update.revision !== "number" ||
      !Number.isSafeInteger(update.revision) ||
      update.revision < 1
    )
      continue;
    const id = update.id.toLowerCase();
    found.set(`${id}:${update.revision}`, { id, revision: update.revision, title: text(update.title, id) });
  }
  return [...found.values()];
}

export function latestScan(jobs: Job[], deviceId: string) {
  return jobs
    .filter((job) => job.device_id === deviceId && job.kind === "windows.scan" && job.state === "succeeded")
    .sort((a, b) => Date.parse(b.finished_at ?? b.created_at) - Date.parse(a.finished_at ?? a.created_at))[0];
}

export function commonUpdates(jobs: Job[], targets: string[], now = Date.now()) {
  const scans = targets.map((id) => latestScan(jobs, id));
  const missing = targets.filter((_id, index) => {
    const scan = scans[index];
    const time = scan ? Date.parse(scan.finished_at ?? scan.created_at) : Number.NaN;
    return !Number.isFinite(time) || now - time > 24 * 3600_000 || time > now + 60_000;
  });
  if (!targets.length || missing.length) return { updates: [] as AvailableUpdate[], missing };
  const sets = scans.map((scan) => availableUpdates(scan?.result ?? null));
  const updates = (sets[0] ?? []).filter((update) =>
    sets.every((set) => set.some((value) => value.id === update.id && value.revision === update.revision)),
  );
  return { updates, missing };
}

export type OperationDraft = { deviceIds: string[]; kind: Job["kind"]; updates?: AvailableUpdate[] };
