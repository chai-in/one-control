import { z } from "zod";

export const contextSchema = z.enum(["system", "user"]);
export const ringSchema = z.enum(["canary", "pilot", "broad"]);
export const packageIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
export const windowsUpdateSchema = z.object({ id: z.uuid(), revision: z.int().min(1) }).strict();
export const commandSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("inventory.scan") }).strict(),
  z.object({ kind: z.literal("windows.scan") }).strict(),
  z.object({ kind: z.literal("indexing.status") }).strict(),
  z
    .object({
      kind: z.literal("indexing.enable"),
      startup: z.enum(["automatic", "automatic-delayed", "manual"]),
    })
    .strict(),
  z.object({ kind: z.literal("indexing.disable") }).strict(),
  z.object({ kind: z.literal("indexing.pause") }).strict(),
  z.object({ kind: z.literal("indexing.resume") }).strict(),
  z
    .object({ kind: z.literal("windows.install"), updates: z.array(windowsUpdateSchema).min(1).max(100) })
    .strict(),
  z
    .object({
      kind: z.literal("winget.upgrade"),
      packageId: packageIdSchema,
      version: z
        .string()
        .regex(/^[A-Za-z0-9][A-Za-z0-9._+()-]{0,63}$/)
        .refine(
          (value) => !["latest", "unknown"].includes(value.toLowerCase()),
          "A pinned package version is required",
        ),
    })
    .strict(),
  z.object({ kind: z.literal("store.upgrade"), packageId: z.string().regex(/^[A-Za-z0-9]{8,32}$/) }).strict(),
  z.object({ kind: z.literal("package.install"), releaseId: z.uuid() }).strict(),
]);
export type Command = z.infer<typeof commandSchema>;
export type ExecutionContext = z.infer<typeof contextSchema>;
export function commandContext(command: Command): ExecutionContext {
  return ["winget.upgrade", "store.upgrade"].includes(command.kind) ? "user" : "system";
}
export function isMutation(command: Command): boolean {
  return !["inventory.scan", "windows.scan", "indexing.status"].includes(command.kind);
}
export const manifestSchema = z
  .object({
    schemaVersion: z.literal(1),
    packageId: packageIdSchema,
    sequence: z.int().min(1),
    version: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._+()-]{0,63}$/),
    artifactUrl: z.url(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    size: z.int().min(1).max(2_147_483_648),
    publisherThumbprint: z.string().regex(/^[A-F0-9]{40}$/),
    expiresAt: z.iso.datetime(),
  })
  .strict()
  .refine(
    (manifest) => {
      if (manifest.packageId !== "one-control-agent") return true;
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,5}$/.test(manifest.version)) return false;
      const [major, minor, build] = manifest.version.split(".").map(Number);
      return (
        major !== undefined &&
        minor !== undefined &&
        build !== undefined &&
        major <= 255 &&
        minor <= 255 &&
        build <= 65535
      );
    },
    { message: "Agent payload requires a valid three-part Windows Installer version", path: ["version"] },
  );
export const envelopeSchema = z
  .object({
    payload: z.string().min(1).max(16_384),
    signature: z.string().min(1).max(1024),
  })
  .strict();
export type SignedEnvelope = z.infer<typeof envelopeSchema>;
export const createJobSchema = z
  .object({
    targets: z.array(z.uuid()).min(1).max(500),
    ring: ringSchema,
    command: commandSchema,
    startsAt: z.iso.datetime(),
    endsAt: z.iso.datetime(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const duration = Date.parse(value.endsAt) - Date.parse(value.startsAt);
    if (duration < 60_000 || duration > 24 * 60 * 60 * 1000)
      ctx.addIssue({ code: "custom", message: "Maintenance window must be 1 minute to 24 hours" });
    if (new Set(value.targets).size !== value.targets.length)
      ctx.addIssue({ code: "custom", message: "Targets must be unique" });
  });
export type CreateJob = z.infer<typeof createJobSchema>;
export type JobState =
  | "awaiting_approval"
  | "queued"
  | "leased"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "indeterminate";
export interface Device {
  id: string;
  hostname: string;
  ring: z.infer<typeof ringSchema>;
  last_seen_at: string | null;
  inventory: Record<string, unknown> | null;
  management_scope_id?: string | null;
  management_scope_name?: string | null;
  enrollment_id?: string | null;
  revoked_at: string | null;
}
export interface WorkspaceInfo {
  deploymentStage: "poc" | "production";
  deviceLimit: number | null;
  serverTime: string;
}
export interface Job {
  id: string;
  device_id: string;
  kind: Command["kind"];
  state: JobState;
  context: ExecutionContext;
  created_at: string;
  starts_at: string;
  ends_at: string;
  result: Record<string, unknown> | null;
  batch_id: string;
  attempt: number;
  command: Command;
  created_by: string;
  finished_at?: string | null;
}
export interface BatchReview {
  id: string;
  createdBy: string;
  createdAt: string;
  approvedBy: string | null;
  command: Command;
  ring: z.infer<typeof ringSchema>;
  targets: { deviceId: string; hostname: string; startsAt: string; endsAt: string; state: JobState }[];
  release: z.infer<typeof manifestSchema> | null;
  reviewDigest: string;
}
export interface Lease {
  id: string;
  leaseToken: string;
  leaseExpiresAt: string;
  command: Command;
  release: SignedEnvelope | null;
  endsAt: string;
}
