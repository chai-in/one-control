import { z } from "zod";
import type { TransactionQuery } from "../../../apps/control-plane/src/database.js";
import { ApiError, hash } from "../../../apps/control-plane/src/security.js";

const decimal = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const unavailable = z.strictObject({
  status: z.literal("unavailable"),
  reason: z.enum(["procedure_unavailable", "query_failed", "invalid_result"]),
});
const unsupported = z.strictObject({
  status: z.literal("unsupported"),
  reason: z.literal("platform_unsupported"),
});
const outside = z.strictObject({
  status: z.literal("unsupported"),
  reason: z.literal("outside_collector_scope"),
});
function observation<T extends z.ZodType>(value: T) {
  return z.union([z.strictObject({ status: z.literal("available"), value }), unavailable, unsupported]);
}
const uint = z.number().int().min(0).max(4294967295);
const inventory = z.strictObject({
  schemaVersion: z.literal(1),
  collectedAt: z.iso.datetime(),
  hostname: observation(z.string().regex(/^[A-Za-z0-9_-]{1,253}$/)),
  osVersion: observation(z.strictObject({ major: uint.min(1), minor: uint, build: uint.min(1) })),
  nativeArchitecture: observation(z.enum(["x86", "x64", "arm32", "arm64", "ia64"])),
  processArchitecture: observation(z.enum(["x86", "x64", "arm32", "arm64", "ia64"])),
  cpu: observation(
    z
      .strictObject({ activeLogicalProcessors: uint.min(1), activeProcessorGroups: uint.min(1).max(65535) })
      .refine((value) => value.activeLogicalProcessors >= value.activeProcessorGroups),
  ),
  memory: observation(
    z
      .strictObject({
        totalBytes: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
        availableBytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
      })
      .refine((value) => value.availableBytes <= value.totalBytes),
  ),
  elapsedSinceStartMilliseconds: observation(z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)),
  serverContact: outside,
  bootIdentity: outside,
  powerState: outside,
});
const common = { sequence: decimal, policyDigest: z.string().regex(/^[a-f0-9]{64}$/) };
export const nativeReportSchema = z.discriminatedUnion("kind", [
  z.strictObject({ ...common, kind: z.literal("heartbeat") }),
  z.strictObject({
    ...common,
    kind: z.literal("inventory"),
    moduleVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
    report: inventory,
  }),
]);
export const nativeObservationSchema = [
  `CREATE TABLE native_report_streams (
    enrollment_id uuid PRIMARY KEY REFERENCES native_enrollments(id), sequence numeric(20,0) NOT NULL CHECK(sequence BETWEEN 1 AND 18446744073709551615),
    digest text NOT NULL, response jsonb NOT NULL, received_at timestamptz NOT NULL DEFAULT clock_timestamp()
  )`,
  `CREATE TABLE native_observations (
    enrollment_id uuid NOT NULL REFERENCES native_enrollments(id), sequence numeric(20,0) NOT NULL,
    scope_id uuid NOT NULL REFERENCES management_scopes(id), device_id uuid NOT NULL REFERENCES devices(id),
    policy_id uuid NOT NULL REFERENCES native_publications(id), kind text NOT NULL CHECK(kind IN ('heartbeat','inventory')),
    digest text NOT NULL, payload jsonb NOT NULL, received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(enrollment_id,sequence)
  )`,
  `CREATE INDEX native_observation_latest ON native_observations(scope_id,enrollment_id,kind,sequence DESC)`,
] as const;

export async function recordNativeObservation(
  tx: TransactionQuery,
  enrollment: { id: string; device_id: string; scope_id: string },
  policyId: string,
  input: z.output<typeof nativeReportSchema>,
) {
  const digest = hash(JSON.stringify(input));
  const [stream] = await tx.query<{ sequence: string; digest: string; response: unknown }>(
    "SELECT sequence::text,digest,response FROM native_report_streams WHERE enrollment_id=$1",
    [enrollment.id],
  );
  if (stream?.sequence === input.sequence) {
    if (stream.digest !== digest) throw new ApiError(409, "native_report_sequence_conflict");
    return stream.response;
  }
  const expected = stream ? BigInt(stream.sequence) + 1n : 1n;
  if (BigInt(input.sequence) !== expected) throw new ApiError(409, "native_report_sequence_gap");
  if (input.kind === "inventory") {
    const [time] = await tx.query<{ valid: boolean }>(
      "SELECT $1::timestamptz<=clock_timestamp()+interval '5 minutes' AS valid",
      [input.report.collectedAt],
    );
    if (!time?.valid) throw new ApiError(400, "native_report_future_time");
  }
  const [stored] = await tx.query<{ received_at: Date }>(
    "INSERT INTO native_observations(enrollment_id,sequence,scope_id,device_id,policy_id,kind,digest,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING received_at",
    [
      enrollment.id,
      input.sequence,
      enrollment.scope_id,
      enrollment.device_id,
      policyId,
      input.kind,
      digest,
      JSON.stringify(input),
    ],
  );
  const response = {
    sequence: input.sequence,
    receivedAt: new Date(stored!.received_at).toISOString(),
    source: "native-enrollment",
    deviceId: enrollment.device_id,
    enrollmentId: enrollment.id,
  };
  await tx.query(
    "INSERT INTO native_report_streams(enrollment_id,sequence,digest,response) VALUES($1,$2,$3,$4) ON CONFLICT(enrollment_id) DO UPDATE SET sequence=EXCLUDED.sequence,digest=EXCLUDED.digest,response=EXCLUDED.response,received_at=clock_timestamp()",
    [enrollment.id, input.sequence, digest, JSON.stringify(response)],
  );
  await tx.query("UPDATE devices SET last_seen_at=clock_timestamp() WHERE id=$1", [enrollment.device_id]);
  return response;
}

export async function nativeObservationSnapshot(tx: TransactionQuery, scope: string, version: string) {
  return {
    version,
    devices: await tx.query(
      `SELECT e.id AS enrollment_id,e.device_id,d.hostname,e.platform,e.revoked_at,d.last_seen_at,
    s.sequence::text AS last_sequence,o.payload AS inventory,o.received_at AS inventory_received_at
    FROM native_enrollments e JOIN devices d ON d.id=e.device_id
    LEFT JOIN native_report_streams s ON s.enrollment_id=e.id
    LEFT JOIN LATERAL (SELECT payload,received_at FROM native_observations WHERE enrollment_id=e.id AND kind='inventory' ORDER BY sequence DESC LIMIT 1) o ON true
    WHERE e.scope_id=$1 ORDER BY d.hostname,e.created_at DESC`,
      [scope],
    ),
  };
}
