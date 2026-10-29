import { record, text } from "./view-model.js";

export function bytes(value: unknown) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) return "Not reported";
  if (value < 1024) return `${value} B`;
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), 4);
  return `${new Intl.NumberFormat("en-IN", { maximumFractionDigits: 1 }).format(value / 1024 ** index)} ${["B", "KiB", "MiB", "GiB", "TiB"][index]}`;
}

export function uptime(value: unknown) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) return "Not reported";
  const minutes = Math.floor(value / 60);
  if (minutes === 0) return "Less than a minute";
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  return hours < 24 ? `${hours}h ${minutes % 60}m` : `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

const capacity = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

export function memoryCapacity(inventory: Record<string, unknown> | null) {
  const value = record(record(inventory?.hardware)?.memory);
  if (!capacity(value?.totalBytes) || value.totalBytes === 0) return null;
  return {
    total: value.totalBytes,
    available:
      capacity(value.availableBytes) && value.availableBytes <= value.totalBytes
        ? value.availableBytes
        : null,
  };
}
export type Disk = {
  name: string;
  fileSystem: string;
  system: boolean;
  capacity: { total: number; free: number; percent: number; low: boolean } | null;
};

export function disks(inventory: Record<string, unknown> | null): Disk[] {
  const hardware = record(inventory?.hardware);
  if (!Array.isArray(hardware?.disks)) return [];
  const found = new Map<string, Disk>();
  for (const value of hardware.disks.slice(0, 32)) {
    const item = record(value);
    if (!item || typeof item.name !== "string" || !/^[a-z]:\\$/i.test(item.name)) continue;
    const valid =
      item.status === "available" &&
      capacity(item.totalBytes) &&
      item.totalBytes > 0 &&
      capacity(item.freeBytes) &&
      item.freeBytes <= item.totalBytes;
    const total = valid ? (item.totalBytes as number) : 0;
    const free = valid ? (item.freeBytes as number) : 0;
    const name = item.name.toUpperCase();
    found.set(name, {
      name,
      fileSystem: text(item.fileSystem, "Unknown format"),
      system: item.systemVolume === true,
      capacity: valid ? { total, free, percent: (free / total) * 100, low: free / total < 0.1 } : null,
    });
  }
  return [...found.values()].sort(
    (a, b) => Number(b.system) - Number(a.system) || a.name.localeCompare(b.name),
  );
}

export function coverage(inventory: Record<string, unknown> | null) {
  const collection = record(inventory?.collection);
  const issues = Array.isArray(collection?.issues) ? collection.issues : [];
  const labels = new Set<string>();
  for (const issue of issues.slice(0, 20)) {
    const section = record(issue)?.section;
    if (typeof section !== "string") continue;
    const label = section.startsWith("hardware")
      ? "Hardware"
      : section.startsWith("windows")
        ? "Windows"
        : section === "applications"
          ? "Applications"
          : section === "agent.recovery"
            ? "Recovery status"
            : section === "user.session"
              ? "User session"
              : "Inventory";
    labels.add(label);
  }
  return {
    partial: collection?.status === "partial",
    sections: [...labels],
    machineApplications: collection?.applicationScope === "machine_registry_32_and_64_bit",
  };
}

export function attention(inventory: Record<string, unknown> | null) {
  const signals: { code: string; label: string; tone: string }[] = [];
  if (inventory?.agentRecoveryReady === false)
    signals.push({ code: "recovery", label: "Recovery stopped", tone: "bad" });
  if (disks(inventory).some((disk) => disk.capacity?.low))
    signals.push({ code: "low_space", label: "Low disk space", tone: "warning" });
  if (inventory?.rebootPending === true)
    signals.push({ code: "restart", label: "Restart needed", tone: "warning" });
  if (coverage(inventory).partial)
    signals.push({ code: "partial", label: "Partial inventory", tone: "warning" });
  return signals;
}
